# AGENTS.md - AI Agent Guide for standard_id-void_which_binds

`standard_id-void_which_binds` is a provider plugin for the [StandardId](https://github.com/rarebit-one/standard_id) authentication engine. It signs people in with their organisation's Void-Which-Binds broker (moneta) and deprovisions them when moneta pushes a Security Event Token, per ADR-0023 in [void-which-binds-go](https://github.com/rarebit-one/void-which-binds-go) (`docs/adr/0023-broker-oidc-login-and-set-deprovisioning.md`, including the #135 watermark amendment).

**The protocol lives in void-which-binds-go.** This gem ports its `oidc` and `secevent` verifiers rule for rule, and replays its golden vectors. Never invent protocol semantics here. If the Ruby port and a vector disagree, the vector wins. Fail closed.

## Quick Reference

```bash
bundle exec rspec                              # all specs, including the vector replay
bundle exec rspec spec/protocol                # just the golden vectors
bundle exec rubocop --config .rubocop.yml      # --config is required on Ruby 4.0
scripts/check-vector-drift.sh                  # needs read access to void-which-binds-go
```

## Project Structure

```
lib/standard_id/void_which_binds.rb             # entry: requires, plugin_railtie(:void_which_binds, ...)
lib/standard_id/void_which_binds/
  jose.rb            # compact JWS, strict JSON, JWK/thumbprint, Pins (port of internal/jose)
  id_token.rb        # IdToken.verify / sign (port of oidc.VerifyIDToken / SignIDToken)
  validators.rb      # issuer/client_id/person-id shapes, PKCE S256, Discovery
  security_event.rb  # SET verify/sign, RFC 8935 response/classify, watermark rules (port of secevent)
  configuration.rb   # social.void_which_binds_* readers, HTTP, Broker (endpoints + pinned JWKS cache)
  providers/void_which_binds.rb   # StandardId::Providers::VoidWhichBinds
  logins.rb          # session creation under the watermark (SESSION_CREATED subscriber)
  receiver.rb        # SET application in one transaction
  staff_policy.rb    # login_method_policy for staff
  engine.rb          # Rails engine: route, SESSION_CREATED subscriber
  testing.rb         # test-only token/SET minting for host apps
lib/standard_id/void_which_binds/events_endpoint.rb               # POST /events (bare Rack endpoint)
app/models/standard_id/void_which_binds/                            # Subject, Login, ReceivedEvent
db/migrate/                                                         # the three tables
lib/generators/standard_id/void_which_binds/install/                # install generator
spec/vectors/{oidc,secevent}/                                       # VERBATIM copies; never hand-edit
spec/vectors/VOID_WHICH_BINDS_GO_REF                                # the pinned void-which-binds-go commit
spec/protocol/                                                      # vector replay specs
spec/requests/                                                      # dummy-app request specs
spec/dummy/                                                         # minimal host app (SQLite)
```

## Key Patterns

- **Verdicts:** every refusal is a `StandardId::VoidWhichBinds::Refusal` whose `verdict` is spelled the way the vectors spell it. Keep the check order identical to the Go code, because the vectors pin which refusal comes first.
- **Ed25519:** this gem uses OpenSSL 3 raw keys (`OpenSSL::PKey.new_raw_public_key("ED25519", x)`), not the `ed25519` gem.
- **One transaction:** the jti, the watermark, the revocations, the disabled link and the staff lock commit together, before the `202`. Do not add writes outside it.
- **Vectors:** to update them, copy `testvectors/vectors/oidc` and `secevent` from void-which-binds-go at the new ref, and bump `VOID_WHICH_BINDS_GO_REF` in the same change.

## Dependencies

- **standard_id** `~> 0.46` (core-managed PKCE via `supports_pkce?` and the `callback_iss:` / `code_verifier:` kwargs; `trusted_for_linking?`, `login_method_policy` and the refresh-token auth lineage from 0.45)
- **rails** / **activesupport** `>= 8.1`, **json** `>= 2.13` (`allow_duplicate_key: false`)

## Testing

- No network: WebMock stubs the token endpoint, discovery and the JWKS.
- `spec/spec_helper.rb` rebuilds `spec/dummy/tmp/test.sqlite3` on every run from the dummy's, standard_id's and this gem's migrations.
