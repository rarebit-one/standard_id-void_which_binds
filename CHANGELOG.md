# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`StandardId::Providers::VoidWhichBinds`** (`void_which_binds`): sign-in with
  an organisation's Void-Which-Binds broker (moneta), per ADR-0023. It uses the
  authorization code flow with PKCE S256 (the verifier is derived from the
  server-held nonce), a nonce, `client_secret_basic`, and the callback's
  RFC 9207 `iss` checked before the code is exchanged. The EdDSA ID token is
  verified only under pinned RFC 7638 thumbprints, with void-which-binds-go's
  `oidc.VerifyIDToken` rules. `trusted_for_linking?` is `true` (see the
  README's warning). Requires standard_id 0.45.
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
- **Install generator** `standard_id:void_which_binds:install`: initializer,
  migration (subjects, logins and received-events tables) and the engine mount.
- **`StandardId::VoidWhichBinds::Testing`**: mints ID tokens and SETs under
  test-only keys, for host request specs.
- **Golden vectors**: every case of void-which-binds-go's
  `testvectors/vectors/oidc` (26 files) and `secevent` (25 files) is replayed.
  Tokens are re-signed and re-minted byte for byte. The copies are pinned by
  `spec/vectors/VOID_WHICH_BINDS_GO_REF` and checked by
  `scripts/check-vector-drift.sh` (CI job `vector-drift`).
