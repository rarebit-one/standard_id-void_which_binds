# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-25

### Fixed

- **A refusal by the host's `network_wrapper` (an open circuit) no longer turns sign-in into a
  500.** On a standard_id with `StandardId::NetworkWrapper` (rarebit-one/standard_id#480), broker
  requests run through it, so a refusal by the wrapper itself comes back as core's
  `StandardId::ProviderUnavailableError`. `Http.perform` lets it through, renamed "Void-Which-Binds
  is temporarily unavailable" (the refusal as `cause`), instead of wrapping it in
  `BrokerUnavailable`. Sign-in (web only for this provider) then takes core's path: back to the
  login page with that message. The SET endpoint answers it with 500 (which
  moneta retries), logged as an outage and not reported as an error. Transport errors still
  become `BrokerUnavailable`, and programming errors in the wrapper pass through unchanged. On
  older standard_id releases the wrapper is still called directly and its own error propagates
  as is; the `~> 0.46` requirement is unchanged. The mapping is feature-detected and takes effect
  with standard_id >= 0.63.0.

## [0.1.0] - 2026-11-23

### Added

- **Broker requests honour the host's `StandardId.config.network_wrapper`** (standard_id releases
  after 0.60.0), given `provider: :void_which_binds`: discovery, the JWKS and the token exchange,
  so a circuit breaker or tracing span covers them as it covers the other providers. The gem keeps
  its own HTTP client (the broker may sit on a private address that `StandardId::HttpClient`
  refuses). A transport error raised inside the wrapper still becomes `BrokerUnavailable`; an
  error the wrapper raises itself propagates as is. On older standard_id releases there is no such
  setting, so nothing changes and the `~> 0.46` requirement stays.
- **`StandardId::Providers::VoidWhichBinds`** (`void_which_binds`): sign-in with
  an organisation's Void-Which-Binds broker (moneta), per ADR-0023. It uses the
  authorization code flow with PKCE S256, a nonce, `client_secret_basic`, and
  the callback's RFC 9207 `iss` checked before the code is exchanged. The
  EdDSA ID token is verified only under pinned RFC 7638 thumbprints, with
  void-which-binds-go's `oidc.VerifyIDToken` rules. `trusted_for_linking?` is
  `true` (see the README's warning). Requires standard_id 0.46.
- **`StandardId::VoidWhichBinds.staff_policy`**: a `login_method_policy` that
  admits staff accounts only through `void_which_binds`, gated by
  `void_which_binds_require_for_staff` (default `true`). A staff lock the
  account class cannot perform (no `StandardId::AccountLocking`) is refused at
  boot.
- **SET receiver** at `POST /auth/void_which_binds/events` (RFC 8935). It
  verifies the SET with void-which-binds-go's `secevent.Verify` rules, answers
  with `secevent.Response`'s codes, deduplicates the `jti`, and applies the
  event by watermark in one transaction before the `202`. It is a bare Rack
  endpoint that reads at most 16 KiB + 1 of the body, also for a chunked
  request with no Content-Length.
  - A session-revoked SET revokes sessions with `login_iat <= toe` and records
    the per-subject revocation watermark (#135), even for unknown subjects.
  - An account-disabled SET applies when `toe >= last_login_iat`. It disables
    the link, revokes the account's sessions and refresh tokens, and locks a
    staff account.
  - Session creation refuses an ID token with `iat <=` the watermark or the
    disabled `toe`.
- **Failure attribution at the SET endpoint**: only a defect in the SET is
  answered 400. An unusable inline or fetched JWKS, an unreachable broker, a
  database error or any unexpected error on the receiving side is a 500, which
  moneta retries instead of dead-lettering.
- **Install generator** `standard_id:void_which_binds:install`: initializer,
  migration (subjects, logins and received-events tables) and the engine mount.
- **`StandardId::VoidWhichBinds::Testing`**: mints ID tokens and SETs under
  test-only keys, for host request specs.
- **Golden vectors**: every case of void-which-binds-go's
  `testvectors/vectors/oidc` (26 files) and `secevent` (25 files) is replayed.
  Tokens are re-signed and re-minted byte for byte. The copies are pinned to
  void-which-binds-go **v0.24.0** (`3f97570`) by
  `spec/vectors/VOID_WHICH_BINDS_GO_REF` and checked by
  `scripts/check-vector-drift.sh` (CI job `vector-drift`).

### Changed

- **The PKCE verifier and the callback `iss` now come from standard_id core**
  (0.46's core hook, standard_id#369). The provider declares
  `supports_pkce? = true`, so core generates a fresh verifier for every
  sign-in, keeps it in the encrypted pending-requests cookie, and sends the
  S256 challenge, which `authorization_url` now uses (and refuses to build a
  URL without). `get_user_info` takes `callback_iss:` and `code_verifier:`:
  it refuses a callback whose `iss` is missing or is not
  `void_which_binds_issuer`, refuses a call with no verifier (only the web
  callback passes one, so the native/API callback stays refused), and sends
  the verifier in the token request. Removed: the `CallbackIssuerCheck`
  `before_action` the engine included into the web callback controller,
  `Current.callback_iss` / `Current.callback_checked`,
  `Providers::VoidWhichBinds.code_verifier_for` (the nonce-derived HMAC
  verifier) and `PKCE_KEY_PURPOSE`. Requires standard_id `>= 0.46.0`.
  **Deploy note:** a sign-in in flight at deploy time was started with the
  old derived challenge and has no stored verifier, so it fails once and the
  person needs to retry.
