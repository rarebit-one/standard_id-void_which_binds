# frozen_string_literal: true

# Stand-ins for standard_id constants newer than the locked release, so the
# paths that use them are covered whichever standard_id the bundle resolves.
module StandIn
  module_function

  # Shaped like core's StandardId::ProviderUnavailableError (rarebit-one/standard_id#480).
  def provider_unavailable_error
    Class.new(StandardId::OAuthError) do
      attr_reader :provider

      def initialize(message = nil, provider: nil)
        @provider = provider
        super(message || "#{provider} is temporarily unavailable")
      end

      def oauth_error_code = :temporarily_unavailable
      def http_status = :service_unavailable
    end
  end
end
