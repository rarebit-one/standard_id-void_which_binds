# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # POST /auth/void_which_binds/events: moneta's RFC 8935 push of a Security
    # Event Token (ADR-0023, "Deprovisioning").
    #
    # Answers exactly as void-which-binds-go's secevent.Response: 202 with an
    # empty body once the event's writes (the watermark included) are durable,
    # also for a duplicate jti, an unknown subject and an event acknowledged
    # without being applied; 400 with {"err","description"} for a refused SET
    # (invalid_key for the key, algorithm or signature, invalid_issuer,
    # invalid_audience, else invalid_request); 500 for this app's own
    # misconfiguration or a database failure, which moneta retries.
    #
    # Not the host's ApplicationController: the request carries no cookie,
    # session or CSRF token; the SET's signature under a pinned key is its
    # only authentication.
    class EventsController < ActionController::API
      def create
        unless request.media_type == SecurityEvent::CONTENT_TYPE
          return refuse(400, SecurityEvent::CODE_INVALID_REQUEST, "Content-Type must be #{SecurityEvent::CONTENT_TYPE}")
        end
        if request.content_length.to_i > Jose::MAX_TOKEN_LEN
          return refuse(400, SecurityEvent::CODE_INVALID_REQUEST, "the body is over #{Jose::MAX_TOKEN_LEN} bytes")
        end

        Receiver.receive(request.raw_post.to_s)
        head :accepted
      rescue Refusal, ExpectError => e
        status, code = SecurityEvent.response(e)
        log(:warn, "refused SET (#{e.respond_to?(:verdict) ? e.verdict : e.class}): answered #{status} #{code}")
        status == 500 ? head(:internal_server_error) : refuse(status, code, "SET refused: #{e.verdict}")
      rescue ConfigurationError => e
        log(:error, "misconfigured: #{e.message}")
        head :internal_server_error
      rescue ActiveRecord::ActiveRecordError => e
        # Nothing was committed (the event is applied in one transaction), so
        # moneta's retry of this 500 applies it in full.
        log(:error, "could not apply SET: #{e.class}: #{e.message}")
        Rails.error.report(e, handled: true, source: "standard_id-void_which_binds")
        head :internal_server_error
      end

      private

      def refuse(status, code, description)
        render json: { err: code, description: description }, status: status
      end

      def log(level, message)
        StandardId.logger&.public_send(level, "[StandardId::VoidWhichBinds] #{message}")
      end
    end
  end
end
