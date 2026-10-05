# frozen_string_literal: true

require "spec_helper"
require "standard_id/testing/provider_examples"

RSpec.describe "standard_id-void_which_binds registration" do
  # Every field but the boolean, which casts the shared example's string probe.
  it_behaves_like "a registered StandardId provider", :void_which_binds,
                  config_fields: StandardId::Providers::VoidWhichBinds.config_schema.keys - [:void_which_binds_require_for_staff]

  it "registers StandardId::Providers::VoidWhichBinds" do
    expect(StandardId::ProviderRegistry.get(:void_which_binds)).to eq(StandardId::Providers::VoidWhichBinds)
  end

  it "is registered by the Railtie standard_id's plugin_railtie defines" do
    expect(StandardId::Providers::Railties::VoidWhichBinds).to be < Rails::Railtie
  end

  it "is trusted for cross-provider linking (the org's own IdP)" do
    expect(StandardId::Providers::VoidWhichBinds.trusted_for_linking?).to be(true)
  end

  it "is switched on by void_which_binds_client_id and requires the rest" do
    provider = StandardId::Providers::VoidWhichBinds
    expect(provider.enabling_config_field).to eq(:void_which_binds_client_id)
    expect(provider.required_config_fields).to contain_exactly(
      :void_which_binds_client_secret, :void_which_binds_issuer, :void_which_binds_org, :void_which_binds_jwks_pins
    )
  end

  it "mounts the SET endpoint" do
    route = StandardId::VoidWhichBinds::Engine.routes.routes.find { |r| r.path.spec.to_s.start_with?("/events") }
    expect(route.verb).to eq("POST")
    expect(route.app.app).to eq(StandardId::VoidWhichBinds::EventsEndpoint)
  end
end
