# frozen_string_literal: true

require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "action_mailer/railtie"
require "active_job/railtie"

require "standard_id"
require "standard_id/void_which_binds"

# A minimal host app: standard_id's web engine for sign-in, this gem's engine
# for the SET endpoint, an Account model with locking, and SQLite.
module Dummy
  class Application < Rails::Application
    config.load_defaults Rails::VERSION::STRING.to_f
    config.root = File.expand_path("..", __dir__)
    config.eager_load = false
    config.logger = Logger.new(IO::NULL)
    config.secret_key_base = "standard_id-void_which_binds-test-secret-key-base"
    config.hosts.clear
    config.action_controller.allow_forgery_protection = false
    config.action_dispatch.show_exceptions = :rescuable
    config.consider_all_requests_local = true
    config.cache_store = :null_store
    config.active_support.deprecation = :stderr
    config.action_mailer.delivery_method = :test
    config.action_mailer.default_url_options = { host: "www.example.com" }

    # Consumers run with strict loading on and raising; so does the dummy, so
    # a lazy association read in this gem fails here first.
    config.active_record.strict_loading_by_default = true
    config.active_record.action_on_strict_loading_violation = :raise
  end
end
