# frozen_string_literal: true

require "spec_helper"

# Http honours the host's StandardId `config.network_wrapper` (standard_id
# releases after 0.60.0). On older standard_id releases the setting is not in
# the schema: reading it returns nil and assigning it just stores the value, so
# these examples run the same against either.
RSpec.describe StandardId::VoidWhichBinds::Http, "network_wrapper" do
  let(:url) { "https://broker.example.com/.well-known/openid-configuration" }

  before { stub_request(:get, url).to_return(status: 200, body: "{}") }
  after { StandardId.config.network_wrapper = nil }

  it "makes the request directly when no wrapper is configured" do
    StandardId.config.network_wrapper = nil

    expect(described_class.get(url).code).to eq("200")
  end

  it "runs every request through the wrapper with provider: :void_which_binds" do
    providers = []
    StandardId.config.network_wrapper = lambda do |provider:, &block|
      providers << provider
      block.call
    end
    stub_request(:post, "https://broker.example.com/token").to_return(status: 200, body: "{}")

    expect(described_class.get(url).code).to eq("200")
    described_class.post_form("https://broker.example.com/token", { grant_type: "authorization_code" })

    expect(providers).to eq(%i[void_which_binds void_which_binds])
  end

  it "accepts a wrapper that declares no provider keyword" do
    StandardId.config.network_wrapper = ->(&block) { block.call }

    expect(described_class.get(url).code).to eq("200")
  end

  it "still turns a transport error raised inside the wrapper into BrokerUnavailable" do
    stub_request(:get, url).to_timeout
    StandardId.config.network_wrapper = ->(provider:, &block) { block.call }

    expect { described_class.get(url) }
      .to raise_error(StandardId::VoidWhichBinds::BrokerUnavailable, /broker.example.com is unreachable/)
  end

  it "lets an error the wrapper raises itself propagate, without making the request" do
    circuit_open = Class.new(StandardError)
    StandardId.config.network_wrapper = ->(provider:, &_block) { raise circuit_open, "#{provider} open" }

    expect { described_class.get(url) }.to raise_error(circuit_open, "void_which_binds open")
    expect(WebMock).not_to have_requested(:get, url)
  end
end
