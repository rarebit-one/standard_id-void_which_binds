# frozen_string_literal: true

require "json"
require "rack/request"

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
    # Attribution: only a defect in the SET itself is answered 400. Every
    # failure on this side (configuration, an unusable or unreachable key set,
    # the database, an unexpected error) is a 500, which moneta retries.
    #
    # A bare Rack endpoint, not an ActionController: a controller parses and
    # logs params before its action runs, and for a chunked request (no
    # Content-Length) Rails' Request#content_length reads the WHOLE body to
    # measure it. Here the body is read at most MAX_TOKEN_LEN + 1 bytes,
    # whatever the request claims, so an unauthenticated sender cannot make the
    # app buffer more than that. The request carries no cookie, session or
    # CSRF token; the SET's signature under a pinned key is its only
    # authentication.
    module EventsEndpoint
      JSON_HEADERS = { "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" }.freeze

      module_function

      def call(env)
        request = Rack::Request.new(env)
        return [405, { "allow" => "POST" }, []] unless request.post?
        unless request.media_type == SecurityEvent::CONTENT_TYPE
          return refuse(SecurityEvent::CODE_INVALID_REQUEST, "Content-Type must be #{SecurityEvent::CONTENT_TYPE}")
        end

        token = bounded_body(env)
        return refuse(SecurityEvent::CODE_INVALID_REQUEST, "the body is over #{Jose::MAX_TOKEN_LEN} bytes") if token.nil?

        Receiver.receive(token)
        [202, {}, []]
      rescue Refusal, ExpectError => e
        status, code = SecurityEvent.response(e)
        log(:warn, "refused SET (#{e.verdict}): answered #{status} #{code}")
        status == 500 ? [500, {}, []] : refuse(code, "SET refused: #{e.verdict}")
      rescue ConfigurationError => e
        log(:error, "misconfigured: #{e.message}")
        [500, {}, []]
      rescue ActiveRecord::ActiveRecordError => e
        # Nothing was committed (the event is applied in one transaction), so
        # moneta's retry of this 500 applies it in full.
        log(:error, "could not apply SET: #{e.class}: #{e.message}")
        Rails.error.report(e, handled: true, source: "standard_id-void_which_binds")
        [500, {}, []]
      rescue StandardError => e
        # Anything else (a host hook or predicate raising, a bug) is this
        # app's failure, not the SET's: 500, retried, never a 400 that moneta
        # would dead-letter.
        log(:error, "failed to apply SET: #{e.class}: #{e.message}")
        Rails.error.report(e, handled: true, source: "standard_id-void_which_binds")
        [500, {}, []]
      end

      # The body, or nil when it is over the limit. A declared Content-Length
      # over the limit is refused unread; otherwise at most one byte past the
      # limit is read.
      def bounded_body(env)
        return nil if env["CONTENT_LENGTH"].to_i > Jose::MAX_TOKEN_LEN

        input = env["rack.input"]
        return "" if input.nil?

        body = input.read(Jose::MAX_TOKEN_LEN + 1).to_s
        body.bytesize > Jose::MAX_TOKEN_LEN ? nil : body
      end

      def refuse(code, description)
        [400, JSON_HEADERS.dup, [JSON.generate({ err: code, description: description })]]
      end

      def log(level, message)
        StandardId.logger&.public_send(level, "[StandardId::VoidWhichBinds] #{message}")
      end
    end
  end
end
