# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module StandardId
  module VoidWhichBinds
    # Reads this plugin's `social` config fields (declared by the provider's
    # config_schema) through StandardId.config, the same way every provider
    # plugin reads its credentials.
    module Configuration
      module_function

      def social
        StandardId.config.social
      end

      def client_id
        presence(social.void_which_binds_client_id)
      end

      def client_secret
        presence(social.void_which_binds_client_secret)
      end

      # The org's broker (moneta) origin, exactly as moneta's discovery and
      # tokens spell it: an https origin, no path, no trailing slash.
      def issuer
        value = presence(social.void_which_binds_issuer)
        raise ConfigurationError, "void_which_binds_issuer is not set" if value.nil?

        error = Validators.issuer_error(value)
        raise ConfigurationError, "void_which_binds_issuer #{error}" if error

        value
      end

      # The org id ("ed25519:<64 hex>") every ID token's `org` must equal.
      def org
        value = presence(social.void_which_binds_org)
        raise ConfigurationError, "void_which_binds_org is not an ed25519 org id" unless Validators.ed25519_id?(value)

        value
      end

      # The pinned RFC 7638 thumbprints: an Array, or one String separated by
      # commas or whitespace (the ENV form).
      def pins
        raw = social.void_which_binds_jwks_pins
        list = raw.is_a?(Array) ? raw.map(&:to_s) : raw.to_s.split(/[\s,]+/)
        list = list.map(&:strip).reject(&:empty?)
        raise ConfigurationError, "void_which_binds_jwks_pins is empty: pin at least one thumbprint" if list.empty?

        list
      end

      # The JWKS carried inline (JSON text or a Hash), or nil to fetch
      # issuer + /.well-known/jwks.json.
      def inline_jwks
        value = social.void_which_binds_jwks
        value.is_a?(String) ? presence(value) : value.presence
      end

      def authorization_endpoint
        presence(social.void_which_binds_authorization_endpoint)
      end

      def token_endpoint
        presence(social.void_which_binds_token_endpoint)
      end

      def require_for_staff?
        social.void_which_binds_require_for_staff == true
      end

      def staff_predicate
        social.void_which_binds_staff_predicate
      end

      def presence(value)
        value.is_a?(String) ? value.strip.presence : value.presence
      end
    end

    # The HTTP the relying party does: discovery, the JWKS and the token
    # endpoint, all on the configured issuer. Plain Net::HTTP with TLS
    # verification and short timeouts. Not StandardId::HttpClient: that client
    # refuses private addresses, and an org's broker may well sit on one (a
    # tailnet), while every URL here comes from the host's own configuration,
    # never from a request.
    module Http
      OPEN_TIMEOUT = 5
      READ_TIMEOUT = 10

      module_function

      def get(url)
        uri = https_uri(url)
        request = Net::HTTP::Get.new(uri)
        request["Accept"] = "application/json"
        perform(uri, request)
      end

      def post_form(url, form, basic_auth: nil)
        uri = https_uri(url)
        request = Net::HTTP::Post.new(uri)
        request["Accept"] = "application/json"
        request["Authorization"] = basic_auth if basic_auth
        request.set_form_data(form)
        perform(uri, request)
      end

      def https_uri(url)
        uri = URI.parse(url.to_s)
        raise ConfigurationError, "#{url.inspect} is not an https URL" unless uri.is_a?(URI::HTTPS) && uri.host.present?

        uri
      end

      def perform(uri, request)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.open_timeout = OPEN_TIMEOUT
        http.read_timeout = READ_TIMEOUT
        http.start { |h| h.request(request) }
      end
    end

    # The provider's view of moneta: its endpoints (configured, or from
    # discovery) and the pinned key set, cached in-process.
    module Broker
      DISCOVERY_TTL = 3600
      JWKS_TTL = 300
      # A key the pins name but the cached JWKS lacks triggers a refetch, at
      # most this often (ADR-0023: moneta may publish `next` early, and the RP
      # must see it once it is pinned).
      JWKS_REFETCH_INTERVAL = 30

      @mutex = Mutex.new
      @cache = {}

      class << self
        # [authorization_endpoint, token_endpoint]: the configured ones, else
        # discovery's. A discovered issuer that differs from the configured
        # one is a hard error, and both endpoints must be on its origin.
        def endpoints
          issuer = Configuration.issuer
          configured = [Configuration.authorization_endpoint, Configuration.token_endpoint]
          return configured if configured.all?

          doc = discovery(issuer)
          list = [configured[0] || doc["authorization_endpoint"], configured[1] || doc["token_endpoint"]]
          list.each do |endpoint|
            raise ConfigurationError, "endpoint #{endpoint.inspect} is not on #{issuer}" unless Discovery.endpoint_on_issuer?(endpoint, issuer)
          end
          list
        end

        # The pins over the inline JWKS, or over the fetched one.
        # `refresh: true` refetches (rate-limited) when a pinned key is missing.
        def pins(refresh: false)
          thumbprints = Configuration.pins
          inline = Configuration.inline_jwks
          return Jose::Pins.new(inline, thumbprints) if inline

          Jose::Pins.new(jwks(Configuration.issuer, refresh: refresh), thumbprints)
        end

        # Verify with the cached pins; when the pinned key is not in the cached
        # JWKS (a key pinned after the last fetch), refetch once and retry.
        def with_pins
          yield pins
        rescue Refusal => e
          raise unless e.verdict == "key_not_published" && Configuration.inline_jwks.nil?

          yield pins(refresh: true)
        end

        def reset!
          @mutex.synchronize { @cache = {} }
        end

        private

        def discovery(issuer)
          cached(:discovery, issuer, DISCOVERY_TTL) do
            response = Http.get(issuer + Discovery::PATH)
            raise ConfigurationError, "discovery answered HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

            doc = Jose.strict_object(response.body, "discovery")
            raise ConfigurationError, "discovered issuer differs from void_which_binds_issuer" unless doc["issuer"] == issuer

            doc
          end
        end

        def jwks(issuer, refresh:)
          key = [:jwks, issuer]
          refreshed_at = nil
          @mutex.synchronize do
            entry = @cache[key]
            if entry
              refreshed_at = entry[:refreshed_at]
              fresh = monotonic - entry[:at] < JWKS_TTL
              throttled = refreshed_at && monotonic - refreshed_at < JWKS_REFETCH_INTERVAL
              return entry[:value] if fresh && (!refresh || throttled)
            end
          end

          response = Http.get(issuer + Discovery::JWKS_PATH)
          raise ConfigurationError, "the JWKS answered HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          keys = Jose.parse_jwks(response.body)
          @mutex.synchronize do
            @cache[key] = { value: keys, at: monotonic, refreshed_at: refresh ? monotonic : refreshed_at }
          end
          keys
        end

        def cached(kind, issuer, ttl)
          key = [kind, issuer]
          @mutex.synchronize do
            entry = @cache[key]
            return entry[:value] if entry && monotonic - entry[:at] < ttl
          end
          value = yield
          @mutex.synchronize { @cache[key] = { value: value, at: monotonic } }
          value
        end

        def monotonic
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      end
    end
  end
end
