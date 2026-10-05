# frozen_string_literal: true

require "active_support"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/hash/indifferent_access"
require "standard_id"
require "standard_id/void_which_binds/version"
require "standard_id/void_which_binds/errors"
require "standard_id/void_which_binds/jose"
require "standard_id/void_which_binds/validators"
require "standard_id/void_which_binds/id_token"
require "standard_id/void_which_binds/security_event"
require "standard_id/void_which_binds/configuration"
require "standard_id/void_which_binds/current"
require "standard_id/void_which_binds/providers/void_which_binds"
require "standard_id/void_which_binds/logins"
require "standard_id/void_which_binds/receiver"
require "standard_id/void_which_binds/staff_policy"
require "standard_id/void_which_binds/engine" if defined?(::Rails::Engine)

# Registers the provider from a Railtie's after_initialize (a no-op outside
# Rails). Its config fields are declared earlier, before config/initializers,
# by standard_id's own engine initializer.
StandardId::Providers.plugin_railtie(:void_which_binds, "StandardId::Providers::VoidWhichBinds")
