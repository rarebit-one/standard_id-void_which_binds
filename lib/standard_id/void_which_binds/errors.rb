# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # Base class for everything this gem raises.
    class Error < StandardError; end

    # A token, event or request refused by one of ADR-0023's verifiers.
    #
    # `verdict` is the refusal named exactly as void-which-binds-go's golden
    # vectors spell it (`malformed`, `wrong_type`, `alg`, `kid_not_pinned`,
    # `key_not_published`, `kid_thumbprint_mismatch`, `key_not_ed25519`,
    # `bad_signature`, `wrong_issuer`, `wrong_audience`, `wrong_org`, `nonce`,
    # `expired`, `iat_future`, `forbidden_claim`, `pkce`, `sub_id`, `events`,
    # `unknown_event`, `toe_missing`, `toe_after_iat`, `iat_too_old`,
    # `session_revoked`), so a refusal is comparable with the Go reference
    # without parsing a message.
    class Refusal < Error
      attr_reader :verdict

      def initialize(verdict, detail = nil)
        @verdict = verdict.to_s
        super(detail ? "#{@verdict}: #{detail}" : @verdict)
      end
    end

    # The verifier was asked to check against an incomplete or out-of-range
    # expectation (an empty issuer, no pins, a leeway over 60 s, ...). It is
    # the relying party's own misconfiguration, never the token's: the SET
    # endpoint answers it with a 500 (retried by moneta), not a 400.
    class ExpectError < Error
      def verdict
        "expect"
      end
    end

    # The relying party's configuration is unusable (a missing issuer, a pin
    # that is not a SHA-256 thumbprint, a discovered issuer that differs from
    # the configured one, ...).
    class ConfigurationError < Error; end

    # moneta could not be reached (a timeout, a refused connection, a TLS
    # failure). Like a misconfiguration it is the relying party's side of the
    # exchange, never the SET's: the SET endpoint answers 500, which moneta
    # retries.
    class BrokerUnavailable < ConfigurationError; end
  end
end
