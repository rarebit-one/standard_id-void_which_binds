# standard_id-void_which_binds

StandardId provider plugin for an organisation's Void-Which-Binds broker (moneta): OIDC login with pinned EdDSA ID tokens and Security Event Token deprovisioning, per [ADR-0023](https://github.com/rarebit-one/void-which-binds-go/blob/main/docs/adr/0023-broker-oidc-login-and-set-deprovisioning.md).

- **Sign-in:** authorization code + PKCE S256 + nonce, `client_secret_basic`. The Ed25519 ID token is verified only under **pinned** key thumbprints, with the same rules as void-which-binds-go's `oidc.VerifyIDToken`. The callback's RFC 9207 `iss` is checked before the code is exchanged.
- **Linking:** by `sub` (standard_id's `(provider, sub)` row), or by email only when moneta says `email_verified: true`.
- **Staff policy:** a `login_method_policy` that lets staff accounts in only through Void-Which-Binds.
- **Deprovisioning:** `POST /auth/void_which_binds/events` receives moneta's RFC 8935 SET push. It verifies the SET (`secevent.Verify`), deduplicates the `jti`, and applies it by watermark. All of that commits in one transaction before the `202`.

## Installation

```ruby
# Gemfile
gem "standard_id-void_which_binds"
```

```bash
bin/rails g standard_id:void_which_binds:install   # initializer, migration, route
bin/rails db:migrate
```

The generator writes `config/initializers/standard_id_void_which_binds.rb`, copies the migration, and adds this mount:

```ruby
mount StandardId::VoidWhichBinds::Engine => "/auth/void_which_binds"
```

Register both URLs with moneta for **every** origin you serve: the redirect URI `<origin>/auth/callback/void_which_binds` and the SET push endpoint `<origin>/auth/void_which_binds/events`.

## Configuration

Every field lives in the `social` scope. A field the initializer does not assign falls back to the ENV variable named after it, upper-cased.

| Field | ENV | |
|---|---|---|
| `void_which_binds_client_id` | `VOID_WHICH_BINDS_CLIENT_ID` | Switches the provider on |
| `void_which_binds_client_secret` | `VOID_WHICH_BINDS_CLIENT_SECRET` | Required |
| `void_which_binds_issuer` | `VOID_WHICH_BINDS_ISSUER` | Required. moneta's https origin, byte for byte (no path, no trailing slash) |
| `void_which_binds_org` | `VOID_WHICH_BINDS_ORG` | Required. The org id, `ed25519:<64 hex>` |
| `void_which_binds_jwks_pins` | `VOID_WHICH_BINDS_JWKS_PINS` | Required. RFC 7638 thumbprints of moneta's `assert` key, as an Array or a comma-separated String |
| `void_which_binds_jwks` | `VOID_WHICH_BINDS_JWKS` | Optional JWKS inline. Otherwise it is fetched from `issuer/.well-known/jwks.json` |
| `void_which_binds_authorization_endpoint`, `void_which_binds_token_endpoint` | (same names) | Optional. Otherwise read from discovery, whose `issuer` must equal the configured one. Either way both must be on the issuer's origin |
| `void_which_binds_require_for_staff` | `VOID_WHICH_BINDS_REQUIRE_FOR_STAFF` | Default `true`. Enforces the staff policy and the staff lock |
| `void_which_binds_staff_predicate` | (none, it is a callable) | `->(account) { account.staff? }` |

**Pinning.** The JWKS distributes keys, but it is never a trust root. A token verifies only under a key whose recomputed thumbprint is pinned and equals its `kid`. A published key that is not pinned is ignored. To rotate the key, pin moneta's `next` thumbprint alongside the current one, and drop the old pin once moneta has cut over. When a pinned key is missing from the cached JWKS, the gem refetches it, at most every 30 s.

### Staff accounts

```ruby
StandardId.configure do |c|
  c.social.void_which_binds_staff_predicate = ->(account) { account.staff? }
  c.login_method_policy = StandardId::VoidWhichBinds.staff_policy
  # or: StandardId::VoidWhichBinds.staff_policy(staff_predicate: ..., fallback: other_policy)
end
```

standard_id 0.45 consults the policy before any session or token exists. That covers every flow, including each refresh, which is checked against the original sign-in's method. A staff account may sign in only with `auth_method: :social` and provider `void_which_binds`. When an `account-disabled` SET is applied to a staff account, the account is also locked (`lock!`, if it includes `StandardId::AccountLocking`). The lock stays until someone unlocks it. If a staff lock is configured but the account class does not include `StandardId::AccountLocking`, the app refuses to boot. If it somehow runs anyway, the revocations still commit and the missing lock is logged and reported to `Rails.error`. Without a predicate, the policy raises and fails closed.

## ⚠️ `trusted_for_linking?` is true, and must stay limited to an org's own IdP

This provider returns `true` from `trusted_for_linking?`. Under `link_strategy: :strict`, a Void-Which-Binds login with `email_verified: true` may therefore link to an **existing, verified** account that was created another way (password, Google, ...).

That is safe **only** because moneta is the organisation's **own** broker. Its `email_verified` is true only when the org itself vouches for the address: a link moneta mailed to that address, or an address in a domain the org administers (ADR-0023, D7). Nobody can self-assert an address there.

Never copy this setting to a provider where anyone can register an address (Google, Apple, GitHub, a shared or multi-tenant IdP). Trusting such a provider lets whoever controls an address *at that IdP* take over the account that holds the same address *here*. Every other guard still applies: the provider must report `email_verified`, the existing identifier must itself be verified, and a different `sub` for the same identifier is refused.

## Deprovisioning (RFC 8935 SET push)

moneta pushes one SET per cause (`Content-Type: application/secevent+jwt`). The endpoint answers exactly as `secevent.Response` does:

| Outcome | Answer |
|---|---|
| Applied; a duplicate `jti`; an unknown subject; an event acknowledged without being applied | `202`, empty body |
| Refused key, algorithm or signature (for example a pin gap during a rotation) | `400 {"err":"invalid_key"}`. moneta retries |
| Wrong `iss` / `aud` | `400 invalid_issuer` / `invalid_audience`. moneta retries |
| Anything else (wrong `typ`, a stale `iat`, a malformed claim, ...) | `400 invalid_request`. moneta dead-letters |
| Anything on this side: misconfiguration, an unusable inline or fetched JWKS, moneta unreachable, a database failure, an unexpected error | `500`. moneta retries; nothing was committed |

The gem applies an event by watermark. Every comparison is between stamps from moneta's monotonic clock, and a tie revokes.

- **session-revoked** raises the subject's revocation watermark, even for a subject this app has never seen. It never lowers the watermark. It revokes the browser sessions whose ID token was issued at or before `toe`, along with their refresh tokens, plus any `void_which_binds` refresh token that has no session. Newer sessions are untouched.
- **account-disabled** applies only when `toe >=` the subject's newest login. It disables the link at `toe`, revokes every session and refresh token of the linked account, and locks a staff account.
- **Session creation:** the gem refuses an ID token whose `iat <=` the watermark, or `<=` the disabled `toe`. It checks once when the token verifies, and again under the subject's row lock when the session is created. A later login with `iat >` the disabled `toe` re-enables the link.

`StandardId::VoidWhichBinds::ReceivedEvent.prune!` deletes `jti` rows older than the 7-day window. Schedule it daily.

## Scope (v1)

- **Web sign-in only.** The native/API callback (`/api/oauth/callback/void_which_binds`) is refused, because it can neither check `iss` nor hold a server-side nonce.
- **One issuer per app.** standard_id keys the account link by provider name.
- An ID token without `email` cannot create an account, because standard_id needs an email address. moneta includes `email` with the `email` scope when its directory has one.

## Testing

```ruby
require "standard_id/void_which_binds/testing"

key = StandardId::VoidWhichBinds::Testing.key("current")   # test-only seed
StandardId.config.social.void_which_binds_jwks = StandardId::VoidWhichBinds::Testing.jwks(key)
StandardId.config.social.void_which_binds_jwks_pins = [StandardId::VoidWhichBinds::Testing.thumbprint(key)]
token = StandardId::VoidWhichBinds::Testing.id_token(key, iss:, sub:, aud:, iat: Time.now.to_i, nonce:, org:, email:, email_verified: true)
set = StandardId::VoidWhichBinds::Testing.security_event(key, iss:, aud:, iat:, toe:, sub:, event: StandardId::VoidWhichBinds::SecurityEvent::SESSION_REVOKED, reason: "role_changed", initiating_entity: "admin")
```

## Development

```bash
bundle install
bundle exec rspec                              # includes every golden vector
bundle exec rubocop --config .rubocop.yml
scripts/check-vector-drift.sh                  # spec/vectors vs void-which-binds-go at the pinned ref
```

`spec/vectors/oidc` and `spec/vectors/secevent` are verbatim copies of void-which-binds-go's `testvectors/vectors/`, pinned by `spec/vectors/VOID_WHICH_BINDS_GO_REF` (currently the signed tag v0.24.0, `3f97570`). Never edit them by hand: copy them again and bump the pin in the same change.

## License

MIT. See [LICENSE](LICENSE).
