# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # Captures the web callback's RFC 9207 `iss` for the provider, which
    # standard_id calls with the code, redirect URI and nonce only. Included
    # into standard_id's web callback controller by the engine.
    module CallbackIssuerCheck
      extend ActiveSupport::Concern

      included do
        prepend_before_action :capture_void_which_binds_callback_issuer, only: :callback
      end

      private

      def capture_void_which_binds_callback_issuer
        return unless params[:provider].to_s == StandardId::Providers::VoidWhichBinds::PROVIDER_NAME

        Current.callback_checked = true
        Current.callback_iss = params[:iss].is_a?(String) ? params[:iss] : nil
      end
    end

    # The engine: the SET push endpoint (config/routes.rb), the models behind
    # the watermark (app/models), the migrations (db/migrate, installed with
    # `bin/rails standard_id_void_which_binds:install:migrations`), and the two
    # hooks into standard_id's web sign-in.
    class Engine < ::Rails::Engine
      isolate_namespace StandardId::VoidWhichBinds
      engine_name "standard_id_void_which_binds"

      config.to_prepare do
        controller = StandardId::Web::Auth::Callback::ProvidersController
        controller.include(StandardId::VoidWhichBinds::CallbackIssuerCheck) unless controller < StandardId::VoidWhichBinds::CallbackIssuerCheck
      end

      config.after_initialize do
        StandardId::VoidWhichBinds::Jose.assert_strict_json!
        StandardId::VoidWhichBinds::Engine.subscribe_session_created!
      end

      @subscribed = false

      class << self
        # Records the login_iat of every session created from a verified
        # void_which_binds ID token (and refuses it under the watermark).
        def subscribe_session_created!
          return if @subscribed

          @subscribed = true
          StandardId::Events.subscribe(StandardId::Events::SESSION_CREATED) do |event|
            StandardId::VoidWhichBinds::Logins.record!(event[:session])
          end
        end
      end
    end
  end
end
