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

  context "on a standard_id without StandardId::NetworkWrapper" do
    before do
      hide_const("StandardId::NetworkWrapper")
      hide_const("StandardId::ProviderUnavailableError")
    end

    it "lets an error the wrapper raises itself propagate, without making the request" do
      circuit_open = Class.new(StandardError)
      StandardId.config.network_wrapper = ->(provider:, &_block) { raise circuit_open, "#{provider} open" }

      expect { described_class.get(url) }.to raise_error(circuit_open, "void_which_binds open")
      expect(WebMock).not_to have_requested(:get, url)
    end
  end

  # A stand-in for core's NetworkWrapper / ProviderUnavailableError, so the
  # mapping is covered whichever standard_id the bundle resolves.
  context "on a standard_id whose NetworkWrapper reports a refusal" do
    let(:refusal_class) { Class.new(StandardId::OAuthError) }

    before do
      stub_const("StandardId::ProviderUnavailableError", refusal_class)
      refusal = refusal_class
      stub_const("StandardId::NetworkWrapper", Module.new do
        define_singleton_method(:run) { |provider:, &_block| raise refusal, "#{provider} is temporarily unavailable" }
      end)
    end

    it "turns the refusal into BrokerUnavailable, without making the request" do
      expect { described_class.get(url) }.to raise_error(StandardId::VoidWhichBinds::BrokerUnavailable) { |error|
        expect(error.message).to eq("broker.example.com is unreachable (StandardId::ProviderUnavailableError)")
        expect(error.cause).to be_a(refusal_class)
      }
      expect(WebMock).not_to have_requested(:get, url)
    end
  end

  # Against core's real NetworkWrapper; needs a standard_id that has it (run
  # with a path override until released).
  context "on a standard_id with StandardId::NetworkWrapper" do
    before { skip "needs a standard_id with StandardId::NetworkWrapper" unless defined?(StandardId::NetworkWrapper) }

    it "turns an error the wrapper raises itself into BrokerUnavailable, without making the request" do
      circuit_open = Class.new(StandardError)
      StandardId.config.network_wrapper = ->(provider:, &_block) { raise circuit_open, "oauth_#{provider} is open" }

      expect { described_class.get(url) }.to raise_error(StandardId::VoidWhichBinds::BrokerUnavailable) { |error|
        expect(error.message).to eq("broker.example.com is unreachable (StandardId::ProviderUnavailableError)")
        expect(error.cause).to be_a(StandardId::ProviderUnavailableError)
        expect(error.cause.provider).to eq(:void_which_binds)
        expect(error.cause.cause).to be_a(circuit_open)
      }
      expect(WebMock).not_to have_requested(:get, url)
    end

    it "keeps a transport error raised inside the wrapper a plain BrokerUnavailable" do
      stub_request(:get, url).to_timeout
      StandardId.config.network_wrapper = ->(provider:, &block) { block.call }

      expect { described_class.get(url) }
        .to raise_error(StandardId::VoidWhichBinds::BrokerUnavailable, "broker.example.com is unreachable (Net::OpenTimeout)")
    end
  end
end
