# frozen_string_literal: true

require "digest"
require "openssl"

module StandardId
  module VoidWhichBinds
    # The shapes ADR-0023 fixes for issuers, client ids and person ids, as
    # void-which-binds-go's oidc package checks them.
    module Validators
      # "ed25519:<64 lowercase hex>", in its one canonical spelling.
      ED25519_ID = /\Aed25519:[0-9a-f]{64}\z/
      # "mp:<32 lowercase hex>" (a managed person, roster.NewManagedID).
      MANAGED_ID = /\Amp:[0-9a-f]{32}\z/
      # [a-z0-9][a-z0-9-]{0,63}: a client_id fits a scope path.
      CLIENT_ID = /\A[a-z0-9][a-z0-9-]{0,63}\z/
      # An https origin: lowercase host (a DNS name or an IPv6 literal) and an
      # optional port; no userinfo, path, trailing slash, query or fragment.
      ISSUER = %r{\Ahttps://(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?\z}

      module_function

      def ed25519_id?(value)
        value.is_a?(String) && ED25519_ID.match?(value)
      end

      # A person id as `sub` carries it: sovereign ("ed25519:") or managed
      # ("mp:"). Never a device, passkey or enrol key.
      def person_id?(value)
        value.is_a?(String) && (MANAGED_ID.match?(value) || ED25519_ID.match?(value))
      end

      # nil when `value` is an https origin with no path, no trailing slash, no
      # query, fragment or userinfo, in canonical lowercase form; otherwise why
      # not. (Stricter than Go's url.Parse on exotic hosts, never looser.)
      def issuer_error(value)
        return "is not a string" unless value.is_a?(String)
        return nil if ISSUER.match?(value)

        "#{value.inspect} is not a canonical https origin"
      end

      def client_id_error(value)
        return nil if value.is_a?(String) && CLIENT_ID.match?(value)

        "client_id #{value.inspect} is not [a-z0-9][a-z0-9-]{0,63}"
      end
    end

    # PKCE S256 (RFC 7636), the one code_challenge_method ADR-0023 allows.
    module Pkce
      METHOD = "S256"
      VERIFIER = /\A[A-Za-z0-9\-._~]{43,128}\z/

      module_function

      # base64url(SHA-256(verifier)).
      def s256(verifier)
        Jose.encode(Digest::SHA256.digest(verifier))
      end

      # The authorize endpoint's check: method S256 and a challenge that is 43
      # characters of base64url (a SHA-256). Raises Refusal "pkce".
      def check_challenge!(method, challenge)
        raise Refusal.new("pkce", "code_challenge_method #{method.inspect}, only S256") unless method == METHOD
        raise Refusal.new("pkce", "code_challenge is not a base64url SHA-256") unless Jose.decode(challenge.to_s)&.bytesize == 32

        true
      end

      # The token endpoint's check: a verifier of 43-128 unreserved characters
      # whose S256 equals the challenge (constant time). Raises Refusal "pkce".
      def verify_verifier!(challenge, verifier)
        raise Refusal.new("pkce", "code_verifier is not 43 to 128 unreserved characters") unless verifier.is_a?(String) && VERIFIER.match?(verifier)

        computed = s256(verifier)
        unless challenge.is_a?(String) && challenge.bytesize == computed.bytesize &&
            OpenSSL.fixed_length_secure_compare(computed, challenge)
          raise Refusal.new("pkce", "code_verifier does not match code_challenge")
        end

        true
      end
    end

    # The discovery document (/.well-known/openid-configuration) ADR-0023
    # fixes. The RP's own configuration stays authoritative: a discovered
    # issuer that differs from it is a hard error.
    module Discovery
      JWKS_PATH = "/.well-known/jwks.json"
      PATH = "/.well-known/openid-configuration"
      CLAIMS_SUPPORTED = %w[iss sub aud iat exp auth_time nonce org role amr email email_verified].freeze

      module_function

      # Renders the exact document for `issuer` (the golden vector's bytes).
      def render(issuer, authorization_endpoint, token_endpoint)
        error = Validators.issuer_error(issuer)
        raise ConfigurationError, "issuer #{error}" if error

        [authorization_endpoint, token_endpoint].each do |endpoint|
          raise ConfigurationError, "endpoint #{endpoint.inspect} is not on #{issuer}" unless endpoint_on_issuer?(endpoint, issuer)
        end
        Jose.marshal({
          "issuer" => issuer,
          "authorization_endpoint" => authorization_endpoint,
          "token_endpoint" => token_endpoint,
          "jwks_uri" => issuer + JWKS_PATH,
          "response_types_supported" => ["code"],
          "response_modes_supported" => ["query"],
          "grant_types_supported" => ["authorization_code"],
          "subject_types_supported" => ["public"],
          "id_token_signing_alg_values_supported" => ["EdDSA"],
          "token_endpoint_auth_methods_supported" => ["client_secret_basic"],
          "code_challenge_methods_supported" => ["S256"],
          "scopes_supported" => %w[openid email],
          "claims_supported" => CLAIMS_SUPPORTED,
          "authorization_response_iss_parameter_supported" => true
        })
      end

      # An https URL on the issuer's own origin, with no query or fragment.
      def endpoint_on_issuer?(endpoint, issuer)
        endpoint.is_a?(String) && endpoint.start_with?("#{issuer}/") && !endpoint.match?(/[?#\s]/)
      end
    end
  end
end
