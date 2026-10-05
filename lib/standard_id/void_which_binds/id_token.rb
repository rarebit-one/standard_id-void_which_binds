# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # ADR-0023's ID token: a compact JWS with the header exactly
    # {"alg":"EdDSA","kid":"<thumbprint>","typ":"JWT"}, verified only under a
    # pinned key. A port of void-which-binds-go's oidc.VerifyIDToken; every
    # refusal is a Refusal named as the golden vectors name it.
    module IdToken
      TYP = "JWT"
      # exp - iat (5 minutes).
      LIFETIME = 300
      # The clock-skew allowance on iat and exp. Expect#leeway may be smaller,
      # never larger.
      MAX_LEEWAY = 60

      # The two amr sets ADR-0023 allows (RFC 8176); amr never claims hwk/swk.
      AMR_PASSKEY = %w[mfa pop user].freeze
      AMR_DEVICE = %w[mca pop].freeze
      ROLES = %w[viewer member admin owner].freeze

      # Every claim an ID token carries (nonce is checked by each caller).
      Claims = Struct.new(:iss, :sub, :aud, :iat, :exp, :auth_time, :nonce, :org, :role, :amr, :email, :email_verified,
                          keyword_init: true)

      # What an RP expects of an ID token: its own configuration and the
      # session's nonce. Every field is required.
      Expect = Struct.new(:issuer, :client_id, :org, :nonce, :pins, :now, :leeway, keyword_init: true)

      module_function

      # Verifies `token` and returns its Claims. In order it refuses: a
      # malformed token, typ other than "JWT", alg other than EdDSA/Ed25519, a
      # kid not pinned, a pinned key missing, mis-labelled or not Ed25519, a bad
      # signature (the shared JWS layer), an `events` claim, an aud array, an
      # absent nonce, malformed or missing claims, then iss, aud, org and nonce
      # not as expected, exp != iat + 300, auth_time after iat, an amr outside
      # the two sets (all malformed), exp <= now - leeway (expired) and
      # iat >= now + leeway (iat_future).
      #
      # It does not burn the nonce or check the redirect's RFC 9207 `iss`; the
      # caller does both.
      #
      # @param now [Integer] seconds since the epoch
      # @raise [Refusal] on any refusal
      # @raise [ExpectError] on an incomplete expectation
      def verify(token, expect)
        validate_expect!(expect)

        claims = Jose.verify(token, TYP, expect.pins).claims
        raise Refusal.new("forbidden_claim", "events") if claims.key?("events")
        raise Refusal.new("wrong_audience", "aud is an array") if claims["aud"].is_a?(Array)

        nonce = Jose.string(claims["nonce"])
        raise Refusal.new("nonce", "absent") if nonce.nil?

        c = parse(claims)
        c.nonce = nonce

        raise Refusal, "wrong_issuer" if c.iss != expect.issuer
        raise Refusal, "wrong_audience" if c.aud != expect.client_id
        raise Refusal, "wrong_org" if c.org != expect.org
        raise Refusal.new("nonce", "mismatched") unless secure_equal?(c.nonce, expect.nonce)
        raise Refusal.new("malformed", "exp must be iat + #{LIFETIME}") if c.exp != c.iat + LIFETIME
        raise Refusal.new("malformed", "auth_time is after iat") if c.auth_time > c.iat
        raise Refusal.new("malformed", "amr is neither of the two sets") unless amr_allowed?(c.amr)
        raise Refusal, "expired" unless c.exp > expect.now - expect.leeway
        raise Refusal, "iat_future" unless c.iat < expect.now + expect.leeway

        c
      end

      def validate_expect!(expect)
        ok = expect.is_a?(Expect) &&
          [expect.issuer, expect.client_id, expect.org, expect.nonce].all? { |v| v.is_a?(String) && !v.empty? } &&
          expect.now.is_a?(Integer) && expect.now.positive? &&
          expect.leeway.is_a?(Integer) && expect.leeway.between?(0, MAX_LEEWAY)
        raise ExpectError, "invalid id token verification expectation" unless ok
      end

      # Reads every claim by its exact name, refusing a missing or mistyped
      # one, and checks each claim's shape.
      def parse(m)
        values = {}
        %w[iss sub aud org].each do |name|
          values[name] = Jose.string(m[name]) || raise(Refusal.new("malformed", "#{name} is missing or not a string"))
        end
        %w[iat exp auth_time].each do |name|
          values[name] = Jose.int(m[name]) || raise(Refusal.new("malformed", "#{name} is missing or not a non-negative integer"))
        end
        role = Jose.string(m["role"]) || raise(Refusal.new("malformed", "role is missing or not a string"))
        amr = m["amr"]
        unless amr.is_a?(Array) && !amr.empty? && amr.all? { |v| v.is_a?(String) || v.nil? }
          raise Refusal.new("malformed", "amr is missing or not a non-empty array of strings")
        end

        if m.key?("email") != m.key?("email_verified")
          raise Refusal.new("malformed", "email and email_verified come together")
        end

        email = nil
        email_verified = false
        if m.key?("email")
          email = m["email"]
          raise Refusal.new("malformed", "email is not a non-empty string") unless email.is_a?(String) && !email.empty?

          email_verified = m["email_verified"]
          raise Refusal.new("malformed", "email_verified is not a boolean") unless [true, false].include?(email_verified)
        end

        c = Claims.new(iss: values["iss"], sub: values["sub"], aud: values["aud"], org: values["org"],
                       iat: values["iat"], exp: values["exp"], auth_time: values["auth_time"],
                       role: role, amr: amr.map(&:to_s), email: email, email_verified: email_verified)
        check!(c)
        c
      end

      # The shape every ID token's claims must have, minted or verified.
      def check!(c)
        issuer_error = Validators.issuer_error(c.iss)
        raise Refusal.new("malformed", "iss: #{issuer_error}") if issuer_error
        raise Refusal.new("malformed", "sub is not a person id") unless Validators.person_id?(c.sub)

        client_error = Validators.client_id_error(c.aud)
        raise Refusal.new("malformed", "aud: #{client_error}") if client_error
        raise Refusal.new("malformed", "org is not an ed25519 id") unless Validators.ed25519_id?(c.org)
        raise Refusal.new("malformed", "role #{c.role.inspect}") unless ROLES.include?(c.role)
        raise Refusal.new("malformed", "amr is empty") if c.amr.nil? || c.amr.empty?
        raise Refusal.new("malformed", "email_verified without an email") if c.email.to_s.empty? && c.email_verified
      end

      def amr_allowed?(amr)
        amr == AMR_PASSKEY || amr == AMR_DEVICE
      end

      def secure_equal?(a, b)
        a.bytesize == b.bytesize && OpenSSL.fixed_length_secure_compare(a, b)
      end

      # Mints an ID token for `claims` (a Claims) with an Ed25519 private key
      # (an OpenSSL::PKey). moneta is the only real minter; this exists so the
      # gem can re-mint the golden vectors byte for byte and so host apps can
      # sign test tokens (see StandardId::VoidWhichBinds::Testing). It refuses
      # claims ADR-0023 does not define, as void-which-binds-go's SignIDToken
      # does, and takes the kid from the key.
      def sign(private_key, claims)
        check!(claims)
        raise Refusal.new("malformed", "nonce is empty") if claims.nonce.to_s.empty?
        raise Refusal.new("malformed", "exp must be iat + #{LIFETIME}") if claims.exp != claims.iat + LIFETIME
        raise Refusal.new("malformed", "auth_time is after iat") if claims.auth_time > claims.iat
        raise Refusal.new("malformed", "amr is neither of the two sets") unless amr_allowed?(claims.amr)

        payload = {
          "iss" => claims.iss, "sub" => claims.sub, "aud" => claims.aud, "iat" => claims.iat, "exp" => claims.exp,
          "auth_time" => claims.auth_time, "nonce" => claims.nonce, "org" => claims.org, "role" => claims.role,
          "amr" => claims.amr
        }
        unless claims.email.to_s.empty?
          payload["email"] = claims.email
          payload["email_verified"] = claims.email_verified == true
        end
        Jose.sign(private_key, TYP, Jose.marshal(payload))
      end
    end

    module Jose
      # Mints a compact JWS over `payload` with header
      # {"alg":"EdDSA","kid","typ"}, where kid is the RFC 7638 thumbprint of
      # the key's public half. Ed25519 is deterministic, so for the same key and
      # bytes this reproduces a void-which-binds-go token byte for byte.
      def self.sign(private_key, typ, payload)
        kid = thumbprint(public_jwk(private_key.raw_public_key))
        input = "#{encode(marshal({ "alg" => ALG_EDDSA, "kid" => kid, "typ" => typ }))}.#{encode(payload)}"
        "#{input}.#{encode(private_key.sign(nil, input))}"
      end
    end
  end
end
