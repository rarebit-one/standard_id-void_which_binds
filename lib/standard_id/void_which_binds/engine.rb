# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # The engine: the SET push endpoint (config/routes.rb), the models behind
    # the watermark (app/models), the migrations (db/migrate, installed with
    # `bin/rails standard_id_void_which_binds:install:migrations`), and the
    # SESSION_CREATED subscriber that records each sign-in's login_iat. The
    # callback's `iss` and the PKCE verifier come from standard_id core
    # (0.46+), so the engine no longer hooks the callback controller.
    class Engine < ::Rails::Engine
      isolate_namespace StandardId::VoidWhichBinds
      engine_name "standard_id_void_which_binds"

      config.after_initialize do
        StandardId::VoidWhichBinds::Jose.assert_strict_json!
        StandardId::VoidWhichBinds::Engine.subscribe_session_created!
        StandardId::VoidWhichBinds::Engine.verify_staff_lock!
      end

      @subscribed = false

      class << self
        # A staff lock the account class cannot perform is refused at boot
        # rather than discovered at the first roster removal.
        def verify_staff_lock!
          error = StandardId::VoidWhichBinds::Receiver.staff_lock_configuration_error
          raise StandardId::VoidWhichBinds::ConfigurationError, error if error
        end

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
