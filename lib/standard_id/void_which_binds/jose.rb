# frozen_string_literal: true

require "digest"
require "json"
require "openssl"

module StandardId
  module VoidWhichBinds
    # The compact-JWS layer ADR-0023's two verifiers share: strict parsing of a
    # three-part compact JWS, RFC 8037 OKP JWKs and their RFC 7638 thumbprints,
    # and the relying party's pinned key set.
    #
    # A port of void-which-binds-go's internal/jose, rule for rule, so that
    # every golden vector reaches the same verdict here as there. It is
    # deliberately narrow: the only algorithm is Ed25519 (`alg` "EdDSA", with
    # RFC 9864's "Ed25519" also accepted, ADR-0023 owner decision 3), the only
    # key type an OKP key on Ed25519, and the header is exactly
    # {"alg","kid","typ"}: any other header member (crit, jku, jwk, x5u, ...) is
    # refused rather than interpreted. JSON is parsed strictly: duplicate member
    # names at any depth, trailing data and invalid UTF-8 are malformed, and
    # members are read by their exact names.
    #
    # Ed25519 runs on Ruby's OpenSSL binding (OpenSSL 3 raw keys), not the
    # `ed25519` gem: OpenSSL is already loaded by every Rails app, it is the
    # binding the Ruby core team maintains, and it adds no native dependency to
    # the consumers.
    module Jose
      # Bounds a token before anything is decoded (ADR-0023's tokens are a few
      # hundred bytes).
      MAX_TOKEN_LEN = 16 * 1024
      # Bounds JSON nesting (a SET's sub_id and events are depth 2).
      MAX_DEPTH = 8

      ALG_EDDSA = "EdDSA"
      ALG_ED25519 = "Ed25519"
      HEADER_MEMBERS = %w[alg kid typ].freeze
      MAX_INT64 = (2**63) - 1

      # Unpadded base64url.
      def self.encode(bytes)
        [bytes].pack("m0").tr("+/", "-_").delete("=")
      end

      # Strict unpadded base64url: padding, line breaks, non-zero trailing bits
      # and any character outside the alphabet are refused (nil).
      def self.decode(string)
        return nil unless string.is_a?(String) && string.match?(/\A[A-Za-z0-9_-]*\z/)
        return nil if string.length % 4 == 1

        padded = string.tr("-_", "+/")
        padded += "=" * ((4 - (padded.length % 4)) % 4)
        bytes = padded.unpack1("m0")
        # A non-canonical encoding (non-zero trailing bits) does not round-trip.
        encode(bytes) == string ? bytes : nil
      rescue ArgumentError
        nil
      end

      # Compact JSON exactly as every port renders it (Go's encoding/json with
      # HTML escaping off): member order as given, no whitespace, and U+2028 /
      # U+2029 escaped, which Go always does.
      def self.marshal(value)
        JSON.generate(value).gsub("\u2028", "\\u2028").gsub("\u2029", "\\u2029")
      end

      # Parses `data` as exactly one JSON object of valid UTF-8, refusing
      # duplicate member names at any depth, nesting deeper than MAX_DEPTH and
      # trailing data. Returns the object (a Hash), or raises Refusal
      # "malformed".
      def self.strict_object(data, what = "json")
        text = data.to_s.dup.force_encoding(Encoding::UTF_8)
        raise Refusal.new("malformed", "#{what}: not valid UTF-8") unless text.valid_encoding?

        value = JSON.parse(text, allow_duplicate_key: false, allow_nan: false, max_nesting: false,
                                 create_additions: false)
        raise Refusal.new("malformed", "#{what}: not a JSON object") unless value.is_a?(Hash)
        raise Refusal.new("malformed", "#{what}: nested too deeply") unless depth_ok?(value, 0)

        value
      rescue JSON::ParserError, EncodingError => e
        raise Refusal.new("malformed", "#{what}: #{e.class}")
      end

      # Go's walk: every value sits at a depth (the top object 0, its members
      # 1, ...), and any value deeper than MAX_DEPTH is refused.
      def self.depth_ok?(value, depth)
        return false if depth > MAX_DEPTH

        case value
        when Hash then value.each_value.all? { |v| depth_ok?(v, depth + 1) }
        when Array then value.all? { |v| depth_ok?(v, depth + 1) }
        else true
        end
      end

      # A NumericDate written as a non-negative JSON integer within int64.
      def self.int(value)
        value.is_a?(Integer) && value >= 0 && value <= MAX_INT64 ? value : nil
      end

      def self.string(value)
        value.is_a?(String) ? value : nil
      end

      # RFC 7638 SHA-256 thumbprint of an OKP key (RFC 8037 §2):
      # base64url(SHA-256({"crv","kty","x"})), the required members in
      # lexicographic order with no whitespace. Reads only those three members.
      def self.thumbprint(jwk)
        jwk = jwk.transform_keys(&:to_s)
        encode(Digest::SHA256.digest(marshal({ "crv" => jwk["crv"].to_s, "kty" => jwk["kty"].to_s, "x" => jwk["x"].to_s })))
      end

      # This profile's JWK for a raw 32-byte Ed25519 public key, in its
      # rendering order {"kty","crv","x","kid","use","alg"}.
      def self.public_jwk(raw_public_key)
        jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => encode(raw_public_key) }
        { "kty" => "OKP", "crv" => "Ed25519", "x" => jwk["x"], "kid" => thumbprint(jwk), "use" => "sig", "alg" => ALG_EDDSA }
      end

      # Parses a key set strictly: one JSON object with a "keys" array of
      # objects, and each of kty, crv, x, kid, use and alg, where present, a
      # string. Other members are ignored. Accepts the JSON text or an
      # already-parsed Hash.
      def self.parse_jwks(raw)
        top = raw.is_a?(Hash) ? raw.transform_keys(&:to_s) : strict_object(raw, "jwks")
        keys = top["keys"]
        raise Refusal.new("malformed", "jwks: keys is missing or not an array") unless keys.is_a?(Array)

        keys.each_with_index.map do |entry, i|
          raise Refusal.new("malformed", "jwks: key #{i} is not an object") unless entry.is_a?(Hash)

          entry = entry.transform_keys(&:to_s)
          %w[kty crv x kid use alg].each_with_object({}) do |name, jwk|
            next unless entry.key?(name)
            raise Refusal.new("malformed", "jwks: key #{i} member #{name} is not a string") unless entry[name].is_a?(String)

            jwk[name] = entry[name]
          end
        end
      end

      # An RP's trust root (ADR-0023, "Pinning"): a non-empty set of pinned
      # thumbprints, and the key set (fetched from the JWKS, or carried inline)
      # the pinned keys are looked up in. The JWKS distributes keys but is never
      # trusted on its own: a token verifies only under a key whose RECOMPUTED
      # thumbprint is pinned and equals the token's kid. A published key that is
      # not pinned is ignored.
      class Pins
        attr_reader :thumbprints, :keys

        # @param keys [Array<Hash>, Hash, String] parsed JWKs, a JWKS Hash, or JWKS JSON
        # @param thumbprints [Array<String>] each 43 characters of base64url (a SHA-256)
        def initialize(keys, thumbprints)
          thumbprints = Array(thumbprints)
          raise ConfigurationError, "the pin set is empty" if thumbprints.empty?

          thumbprints.each do |t|
            bytes = Jose.decode(t.to_s)
            raise ConfigurationError, "pin #{t.inspect} is not a base64url SHA-256 thumbprint" unless bytes&.bytesize == 32
          end
          @thumbprints = thumbprints.map(&:to_s).uniq.freeze
          @keys = (keys.is_a?(Array) ? keys.map { |k| k.transform_keys(&:to_s) } : Jose.parse_jwks(keys)).freeze
        end

        def pinned?(kid)
          @thumbprints.include?(kid)
        end

        # The OpenSSL Ed25519 public key for a header kid, refusing exactly as
        # void-which-binds-go's Pins.key does.
        def key(kid)
          raise Refusal, "kid_not_pinned" unless pinned?(kid)

          named = false
          @keys.each do |jwk|
            if Jose.thumbprint(jwk) != kid
              named ||= jwk["kid"] == kid
              next
            end
            raise Refusal.new("kid_thumbprint_mismatch", "the key with thumbprint #{kid} states another kid") if jwk["kid"] != kid
            raise Refusal.new("key_not_ed25519", "kty #{jwk["kty"].inspect} crv #{jwk["crv"].inspect}") if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519"
            raise Refusal.new("key_not_ed25519", "use #{jwk["use"].inspect}") if !jwk["use"].to_s.empty? && jwk["use"] != "sig"
            if !jwk["alg"].to_s.empty? && ![ALG_EDDSA, ALG_ED25519].include?(jwk["alg"])
              raise Refusal.new("key_not_ed25519", "alg #{jwk["alg"].inspect}")
            end

            x = Jose.decode(jwk["x"].to_s)
            raise Refusal.new("key_not_ed25519", "x is not 32 bytes of base64url") unless x&.bytesize == 32

            return OpenSSL::PKey.new_raw_public_key("ED25519", x)
          end
          raise Refusal.new("kid_thumbprint_mismatch", "a key states kid #{kid} but its thumbprint differs") if named

          raise Refusal, "key_not_published"
        end
      end

      # A verified compact JWS: its payload's top-level members and the pinned
      # thumbprint it verified under.
      Token = Struct.new(:claims, :kid)

      # Parses `token` and checks, in this order: its shape (malformed), the
      # header's `typ` equals `typ` (wrong_type), `alg` (alg), `kid` is pinned
      # (kid_not_pinned), the key set holds that key (key_not_published,
      # kid_thumbprint_mismatch, key_not_ed25519), and the signature
      # (bad_signature). Only then is the payload parsed (malformed).
      def self.verify(token, typ, pins)
        raise Refusal.new("kid_not_pinned", "no pinned thumbprints") if pins.nil? || pins.thumbprints.empty?
        raise Refusal.new("malformed", "not a string") unless token.is_a?(String)
        raise Refusal.new("malformed", "#{token.bytesize} bytes, over #{MAX_TOKEN_LEN}") if token.bytesize > MAX_TOKEN_LEN

        parts = token.split(".", -1)
        raise Refusal.new("malformed", "#{parts.size} parts, a compact JWS has 3") unless parts.size == 3

        header_bytes, payload_bytes, signature = parts.map { |part| Jose.decode(part) }
        raise Refusal.new("malformed", "header is not base64url") if header_bytes.nil?
        raise Refusal.new("malformed", "payload is not base64url") if payload_bytes.nil?
        raise Refusal.new("malformed", "signature is not base64url") if signature.nil?

        header = strict_object(header_bytes, "header")
        extra = header.keys - HEADER_MEMBERS
        raise Refusal.new("malformed", "header member #{extra.first.inspect} (the header is exactly alg, kid, typ)") if extra.any?

        got_typ = string(header["typ"])
        raise Refusal.new("wrong_type", "header typ is missing or not a string") if got_typ.nil?
        raise Refusal.new("wrong_type", "typ #{got_typ.inspect}, want #{typ.inspect}") if got_typ != typ

        alg = string(header["alg"])
        raise Refusal.new("alg", "alg #{header["alg"].inspect}") unless [ALG_EDDSA, ALG_ED25519].include?(alg)

        kid = string(header["kid"])
        raise Refusal.new("kid_not_pinned", "header kid is missing or not a string") if kid.nil?

        public_key = pins.key(kid)
        raise Refusal, "bad_signature" unless signature.bytesize == 64 && ed25519_verify(public_key, signature, "#{parts[0]}.#{parts[1]}")

        Token.new(strict_object(payload_bytes, "payload"), kid)
      end

      def self.ed25519_verify(public_key, signature, input)
        public_key.verify(nil, signature, input)
      rescue OpenSSL::PKey::PKeyError
        false
      end

      # The duplicate-member refusal rests on JSON.parse's
      # `allow_duplicate_key: false` (json >= 2.13). An older json would ignore
      # the option and silently take the last duplicate, so check once that it
      # is honoured rather than fail open.
      def self.assert_strict_json!
        JSON.parse('{"a":1,"a":2}', allow_duplicate_key: false)
        raise ConfigurationError, "json #{JSON::VERSION} accepts duplicate members; standard_id-void_which_binds needs json >= 2.13"
      rescue JSON::ParserError
        true
      end
    end
  end
end
