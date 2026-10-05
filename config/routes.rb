# frozen_string_literal: true

# Mounted by the host at /auth/void_which_binds (the install generator adds
#   mount StandardId::VoidWhichBinds::Engine => "/auth/void_which_binds"
# to config/routes.rb), so moneta's SET push endpoint is
# POST /auth/void_which_binds/events.
StandardId::VoidWhichBinds::Engine.routes.draw do
  post "events", to: "events#create", as: :events
end
