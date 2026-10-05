# frozen_string_literal: true

require "standard_id/void_which_binds"

module StandardId
  module VoidWhichBinds
    # Test support for host apps: mint ID tokens and SETs the way moneta does,
    # under a test-only key, so request specs can drive a real sign-in and a
    # real deprovisioning push without a broker.
    #
    #   require "standard_id/void_which_binds/testing"
    #
    #   key = StandardId::VoidWhichBinds::Testing.key("current")
    #   StandardId.config.social.void_which_binds_jwks = StandardId::VoidWhichBinds::Testing.jwks(key)
    #   StandardId.config.social.void_which_binds_jwks_pins = [StandardId::VoidWhichBinds::Testing.thumbprint(key)]
    #
    # Never use these keys outside tests: the seed is derived from a public
    # label.
    module Testing
      module_function

      # The Ed25519 key void-which-binds-go's golden vectors use for `label`:
      # its seed is SHA-256("void-which-binds/testvectors/adr-0023/" + label).
      def key(label)
        seed_key([Digest::SHA256.hexdigest("void-which-binds/testvectors/adr-0023/#{label}")].pack("H*"))
      end

      # The Ed25519 private key for a raw 32-byte seed.
      def seed_key(seed)
        OpenSSL::PKey.new_raw_private_key("ED25519", seed)
      end

      def jwk(key)
        Jose.public_jwk(key.raw_public_key)
      end

      def thumbprint(key)
        jwk(key)["kid"]
      end

      def jwks(*keys)
        { "keys" => keys.map { |k| jwk(k) } }
      end

      # An ID token for `claims` (a Hash of IdToken::Claims members). exp
      # defaults to iat + 300 and auth_time to iat.
      def id_token(key, **claims)
        claims[:exp] ||= claims[:iat] + IdToken::LIFETIME
        claims[:auth_time] ||= claims[:iat]
        claims[:amr] ||= IdToken::AMR_PASSKEY
        claims[:role] ||= "member"
        IdToken.sign(key, IdToken::Claims.new(**claims))
      end

      # A SET (SecurityEvent::SET members). sub_iss defaults to iss and txn to
      # a fixed string; jti to 16 random bytes.
      def security_event(key, **fields)
        fields[:sub_iss] ||= fields[:iss]
        fields[:txn] ||= "test-txn"
        fields[:jti] ||= Jose.encode(SecureRandom.random_bytes(SecurityEvent::JTI_LEN))
        SecurityEvent.sign(key, SecurityEvent::SET.new(**fields))
      end
    end
  end
end
