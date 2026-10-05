# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # ADR-0023's Security Event Tokens: the RFC 8417 SET (profiled by OpenID
    # SSF 1.0) moneta pushes to each relying party, its verification here, the
    # RFC 8935 answer, and the watermark rules a verified SET is applied by. A
    # port of void-which-binds-go's secevent package.
    #
    # A SET is a compact JWS with the header exactly
    # {"alg":"EdDSA","kid":"<thumbprint>","typ":"secevent+jwt"}, signed by the
    # same `assert` key as the ID token and verified under the same pins. Its
    # payload is, in byte order:
    #
    #   {"iss","aud","jti","iat","toe","txn","sub_id":{"format":"iss_sub","iss","sub"},
    #    "events":{"<one event type URI>":{...}}}
    #
    # with no JWT sub, no exp and exactly one event.
    module SecurityEvent
      TYP = "secevent+jwt"
      CONTENT_TYPE = "application/secevent+jwt"

      SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
      ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

      # The causes a session-revoked SET's reason_admin {"en": ...} carries.
      CAUSES = %w[roster_remove role_expired role_changed key_removed code_replayed regenesis].freeze
      ENTITIES = %w[admin user policy].freeze

      # The oldest iat accepted, and how long a jti must be remembered: 7 days.
      MAX_AGE = 7 * 24 * 60 * 60
      # How far in the future an iat may be: 60 s.
      FUTURE_LEEWAY = 60
      # A jti is 16 random bytes, base64url.
      JTI_LEN = 16

      # The RFC 8935 §2.4 error codes.
      CODE_INVALID_REQUEST = "invalid_request"
      CODE_INVALID_KEY = "invalid_key"
      CODE_INVALID_ISSUER = "invalid_issuer"
      CODE_INVALID_AUDIENCE = "invalid_audience"
      CODE_AUTHENTICATION_FAILED = "authentication_failed"
      CODE_ACCESS_DENIED = "access_denied"
      RETRYABLE_CODES = [CODE_INVALID_KEY, CODE_INVALID_ISSUER, CODE_INVALID_AUDIENCE,
                         CODE_AUTHENTICATION_FAILED, CODE_ACCESS_DENIED].freeze
      KEY_VERDICTS = %w[kid_not_pinned key_not_published kid_thumbprint_mismatch key_not_ed25519 bad_signature alg].freeze

      # A verified SET. `event` is the one event type URI; `initiating_entity`
      # and `reason` are session-revoked's (nil for account-disabled).
      SET = Struct.new(:iss, :aud, :jti, :iat, :toe, :txn, :sub_iss, :sub, :event, :initiating_entity, :reason,
                       keyword_init: true) do
        def session_revoked?
          event == SESSION_REVOKED
        end

        def account_disabled?
          event == ACCOUNT_DISABLED
        end
      end

      # What an RP expects of a SET. Every field is required.
      Expect = Struct.new(:issuer, :audience, :pins, :now, :max_age, keyword_init: true)

      module_function

      # Step 1 and the window half of step 2 of ADR-0023's RP contract. In
      # order it refuses: the JWS layer (malformed, typ other than
      # "secevent+jwt", alg, kid not pinned, the pinned key, bad signature); a
      # JWT sub, exp or nonce; an aud array; malformed claims; a missing toe;
      # iss and aud not as expected; a sub_id that is not iss_sub of this
      # issuer; anything but exactly one known, well-formed event; toe > iat;
      # iat older than max_age or more than 60 s ahead. The caller then
      # deduplicates the jti and applies the event by watermark.
      #
      # @raise [Refusal] on any refusal
      # @raise [ExpectError] on an incomplete expectation
      def verify(token, expect)
        validate_expect!(expect)

        m = Jose.verify(token, TYP, expect.pins).claims
        %w[sub exp nonce].each do |name|
          raise Refusal.new("forbidden_claim", name) if m.key?(name)
        end
        raise Refusal.new("wrong_audience", "aud is an array") if m["aud"].is_a?(Array)

        strings = %w[iss aud jti].to_h do |name|
          [name, Jose.string(m[name]) || raise(Refusal.new("malformed", "#{name} is missing or not a string"))]
        end
        raise Refusal.new("malformed", "jti is not #{JTI_LEN} bytes of base64url") unless Jose.decode(strings["jti"])&.bytesize == JTI_LEN

        iat = Jose.int(m["iat"]) || raise(Refusal.new("malformed", "iat is missing or not a non-negative integer"))
        raise Refusal, "toe_missing" unless m.key?("toe")

        toe = Jose.int(m["toe"]) || raise(Refusal.new("malformed", "toe is not a non-negative integer"))
        # A zero toe would revoke nothing and set the watermark to 0, yet be
        # answered 202: treated as missing, as the minter does.
        raise Refusal.new("toe_missing", "toe is 0") if toe.zero?

        txn = nil
        if m.key?("txn")
          txn = Jose.string(m["txn"]) || raise(Refusal.new("malformed", "txn is not a string"))
        end

        raise Refusal, "wrong_issuer" if strings["iss"] != expect.issuer
        raise Refusal, "wrong_audience" if strings["aud"] != expect.audience

        sub = parse_sub_id(m["sub_id"], strings["iss"])
        event, entity, reason = parse_event(m["events"], toe)

        raise Refusal, "toe_after_iat" if toe > iat
        raise Refusal, "iat_too_old" if iat < expect.now - expect.max_age
        raise Refusal, "iat_future" if iat > expect.now + FUTURE_LEEWAY

        SET.new(iss: strings["iss"], aud: strings["aud"], jti: strings["jti"], iat: iat, toe: toe, txn: txn,
                sub_iss: strings["iss"], sub: sub, event: event, initiating_entity: entity, reason: reason)
      end

      def validate_expect!(expect)
        ok = expect.is_a?(Expect) &&
          [expect.issuer, expect.audience].all? { |v| v.is_a?(String) && !v.empty? } &&
          expect.now.is_a?(Integer) && expect.now.positive? &&
          expect.max_age.is_a?(Integer) && expect.max_age.positive? && expect.max_age <= MAX_AGE
        raise ExpectError, "invalid SET verification expectation" unless ok
      end

      def parse_sub_id(raw, iss)
        raise Refusal.new("sub_id", "not a three-member object") unless raw.is_a?(Hash) && raw.size == 3

        format = raw["format"]
        sub_iss = Jose.string(raw["iss"])
        sub = Jose.string(raw["sub"])
        raise Refusal.new("sub_id", "format is not iss_sub") if format != "iss_sub" || sub_iss.nil? || sub.nil?
        raise Refusal.new("sub_id", "sub_id.iss is not iss") if sub_iss != iss
        raise Refusal.new("sub_id", "sub is not a person id") unless Validators.person_id?(sub)

        sub
      end

      def parse_event(raw, toe)
        raise Refusal.new("events", "#{raw.is_a?(Hash) ? raw.size : 0} events") unless raw.is_a?(Hash) && raw.size == 1

        uri, payload = raw.first
        raise Refusal.new("events", "the event payload is not an object") unless payload.is_a?(Hash)

        case uri
        when ACCOUNT_DISABLED
          # The profile's payload is exactly {}: a RISC reason or any other
          # member is outside it.
          raise Refusal.new("events", "the account-disabled payload is not {}") unless payload.empty?

          [uri, nil, nil]
        when SESSION_REVOKED
          entity = Jose.string(payload["initiating_entity"])
          reasons = payload["reason_admin"]
          reason = reasons.is_a?(Hash) ? Jose.string(reasons["en"]) : nil
          raise Refusal.new("events", "event_timestamp is not toe") unless Jose.int(payload["event_timestamp"]) == toe
          raise Refusal.new("events", "initiating_entity") unless ENTITIES.include?(entity)
          unless payload.size == 3 && reasons.is_a?(Hash) && reasons.size == 1 && CAUSES.include?(reason)
            raise Refusal.new("events", "reason_admin.en")
          end
          raise Refusal.new("events", "role_expired is initiated by policy") if reason == "role_expired" && entity != "policy"

          [uri, entity, reason]
        else
          raise Refusal.new("unknown_event", uri.inspect)
        end
      end

      # The RP's RFC 8935 answer to a verify outcome: [status, err]. nil is
      # 202. An ExpectError is the RP's own misconfiguration: 500, which moneta
      # retries. A refusal of the key, algorithm or signature is invalid_key
      # (the rotation pin gap is one), a wrong iss invalid_issuer, a wrong aud
      # invalid_audience, and anything else invalid_request (dead-lettered).
      def response(error)
        case error
        when nil then [202, ""]
        when ExpectError then [500, ""]
        when Refusal
          return [400, CODE_INVALID_KEY] if KEY_VERDICTS.include?(error.verdict)
          return [400, CODE_INVALID_ISSUER] if error.verdict == "wrong_issuer"
          return [400, CODE_INVALID_AUDIENCE] if error.verdict == "wrong_audience"

          [400, CODE_INVALID_REQUEST]
        else
          [400, CODE_INVALID_REQUEST]
        end
      end

      # Whether a 400 with this RFC 8935 code is retried by the transmitter.
      def retryable?(code)
        RETRYABLE_CODES.include?(code)
      end

      # The transmitter's classification of one delivery attempt's response
      # (moneta's outbox; replayed here so both sides agree on the table):
      # :delivered, :retry or :dead_letter.
      def classify(status, body)
        return :delivered if status == 202
        return :retry unless status == 400

        begin
          object = Jose.strict_object(body.to_s)
        rescue Refusal
          return :dead_letter
        end
        retryable?(Jose.string(object["err"])) ? :retry : :dead_letter
      end

      # The watermark rules (the RP's contract, step 3). Every argument is a
      # stamp from moneta's monotonic clock, so the RP's clock plays no part.
      # A tie revokes: failing closed costs one re-login.

      # A session-revoked SET at toe revokes a session created by an ID token
      # issued at login_iat: login_iat <= toe.
      def revokes_session?(toe, login_iat)
        login_iat <= toe
      end

      # An account-disabled SET at toe applies to a link whose newest login was
      # issued at last_login_iat: toe >= last_login_iat. Otherwise it is
      # acknowledged without being applied (a newer login exists only if the
      # person was re-added).
      def disables_link?(toe, last_login_iat)
        toe >= last_login_iat
      end

      # A login whose ID token was issued at login_iat re-enables a link
      # disabled at disabled_toe: login_iat > disabled_toe.
      def reenables_link?(disabled_toe, login_iat)
        login_iat > disabled_toe
      end

      # Mints a SET (tests and tooling only; moneta is the real transmitter),
      # refusing one ADR-0023 does not define, as void-which-binds-go's Sign
      # does. The kid is taken from the key.
      def sign(private_key, set)
        raise Refusal.new("malformed", "iss") if Validators.issuer_error(set.iss)
        raise Refusal.new("malformed", "aud") if Validators.client_id_error(set.aud)
        raise Refusal.new("malformed", "jti") unless Jose.decode(set.jti.to_s)&.bytesize == JTI_LEN
        raise Refusal.new("malformed", "toe and iat are required") unless set.toe.to_i.positive? && set.iat.to_i.positive?
        raise Refusal, "toe_after_iat" if set.toe > set.iat
        raise Refusal.new("malformed", "txn is empty") if set.txn.to_s.empty?
        raise Refusal, "sub_id" if set.sub_iss != set.iss || !Validators.person_id?(set.sub)

        event =
          case set.event
          when SESSION_REVOKED
            unless CAUSES.include?(set.reason) && ENTITIES.include?(set.initiating_entity)
              raise Refusal.new("events", "session-revoked needs a known cause and initiating entity")
            end
            raise Refusal.new("events", "role_expired is initiated by policy") if set.reason == "role_expired" && set.initiating_entity != "policy"

            { "event_timestamp" => set.toe, "initiating_entity" => set.initiating_entity, "reason_admin" => { "en" => set.reason } }
          when ACCOUNT_DISABLED
            raise Refusal.new("events", "account-disabled carries no cause") if set.reason || set.initiating_entity

            {}
          else
            raise Refusal, "unknown_event"
          end
        payload = {
          "iss" => set.iss, "aud" => set.aud, "jti" => set.jti, "iat" => set.iat, "toe" => set.toe, "txn" => set.txn,
          "sub_id" => { "format" => "iss_sub", "iss" => set.sub_iss, "sub" => set.sub },
          "events" => { set.event => event }
        }
        Jose.sign(private_key, TYP, Jose.marshal(payload))
      end
    end
  end
end
