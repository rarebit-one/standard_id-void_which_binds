# frozen_string_literal: true

Rails.application.routes.draw do
  mount StandardId::WebEngine => "/", as: :standard_id_web
  mount StandardId::VoidWhichBinds::Engine => "/auth/void_which_binds"
  mount StandardId::ApiEngine => "/api", as: :standard_id_api

  get "/dashboard", to: "dashboard#show"
end
