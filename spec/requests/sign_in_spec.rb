# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Signing in with Void-Which-Binds", type: :request do
  before { configure_void_which_binds! }
  after { reset_void_which_binds_config! }

  describe "the authorization redirect" do
    it "sends the code flow with PKCE S256, a nonce and state" do
      params = start_sign_in

      expect(params).to include(
        "client_id" => Vwb::CLIENT_ID,
        "redirect_uri" => Vwb::CALLBACK_URL,
        "response_type" => "code",
        "scope" => "openid email",
        "code_challenge_method" => "S256"
      )
      expect(params["state"]).to be_present
      expect(params["nonce"]).to be_present
      verifier = StandardId::Providers::VoidWhichBinds.code_verifier_for(params["nonce"])
      expect(verifier).to match(/\A[A-Za-z0-9_-]{43}\z/)
      expect(params["code_challenge"]).to eq(StandardId::VoidWhichBinds::Pkce.s256(verifier))
      expect(params.keys).not_to include("code_verifier")
    end

    it "takes the endpoints from discovery when none is configured" do
      configure_void_which_binds!(void_which_binds_authorization_endpoint: nil, void_which_binds_token_endpoint: nil)
      stub_request(:get, "#{Vwb::ISSUER}/.well-known/openid-configuration").to_return(
        status: 200,
        body: StandardId::VoidWhichBinds::Discovery.render(Vwb::ISSUER, Vwb::AUTHORIZATION_ENDPOINT, Vwb::TOKEN_ENDPOINT)
      )

      expect(start_sign_in["client_id"]).to eq(Vwb::CLIENT_ID)
    end

    it "refuses a discovery document for another issuer" do
      configure_void_which_binds!(void_which_binds_authorization_endpoint: nil, void_which_binds_token_endpoint: nil)
      document = JSON.parse(StandardId::VoidWhichBinds::Discovery.render("https://evil.example", "https://evil.example/a", "https://evil.example/t"))
      stub_request(:get, "#{Vwb::ISSUER}/.well-known/openid-configuration").to_return(status: 200, body: JSON.generate(document))

      expect { post "/login", params: { connection: "void_which_binds" } }.to raise_error(StandardId::InvalidRequestError, /misconfigured/)
    end
  end

  describe "the callback" do
    it "creates the account, links (provider, sub) and records the session's login_iat" do
      iat = Time.now.to_i
      sign_in_with_void_which_binds(iat: iat)

      expect(response).to redirect_to("/")
      account = Account.find_by!(email: "person@rarebit.one")
      link = StandardId::SocialIdentity.find_by!(provider: "void_which_binds", subject: Vwb::SUB)
      expect(link.account_id).to eq(account.id)

      session = StandardId::BrowserSession.find_by!(account_id: account.id)
      login = StandardId::VoidWhichBinds::Login.find_by!(session_id: session.id)
      expect([login.iss, login.sub, login.login_iat]).to eq([Vwb::ISSUER, Vwb::SUB, iat])
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).last_login_iat).to eq(iat)
      expect(signed_in?).to be(true)
    end

    it "matches a returning person by sub, whatever email moneta now reports" do
      sign_in_with_void_which_binds(iat: Time.now.to_i - 10)
      account = Account.find_by!(email: "person@rarebit.one")

      sign_in_with_void_which_binds(email: "renamed@rarebit.one")

      expect(response).to redirect_to("/")
      expect(Account.count).to eq(1)
      expect(StandardId::BrowserSession.where(account_id: account.id).count).to eq(2)
    end

    it "links to an existing account by verified email (trusted_for_linking)" do
      account = Account.create!(email: "person@rarebit.one", name: "Person")
      identifier = StandardId::EmailIdentifier.create!(account: account, value: "person@rarebit.one", provider: "google")
      identifier.verify!

      sign_in_with_void_which_binds

      expect(response).to redirect_to("/")
      expect(Account.count).to eq(1)
      expect(StandardId::SocialIdentity.find_by!(provider: "void_which_binds", subject: Vwb::SUB).account_id).to eq(account.id)
    end

    it "refuses to link an existing account when moneta does not vouch for the email" do
      account = Account.create!(email: "person@rarebit.one", name: "Person")
      StandardId::EmailIdentifier.create!(account: account, value: "person@rarebit.one", provider: "google").verify!

      sign_in_with_void_which_binds(email_verified: false)

      expect(response).to have_http_status(:redirect)
      expect(response.location).to include("/login")
      expect(StandardId::SocialIdentity.count).to eq(0)
      expect(StandardId::BrowserSession.count).to eq(0)
    end

    it "refuses a callback without moneta's RFC 9207 iss" do
      sign_in_with_void_which_binds(iss: nil)

      expect(response.location).to include("/login")
      expect(flash[:alert]).to include("callback iss")
      expect(StandardId::BrowserSession.count).to eq(0)
    end

    it "refuses a callback whose iss is another issuer" do
      sign_in_with_void_which_binds(iss: "https://other.example")

      expect(flash[:alert]).to include("callback iss")
      expect(Account.count).to eq(0)
    end

    it "refuses an ID token signed by a key that is published but not pinned" do
      attacker = testing.key("attacker")
      configure_void_which_binds!(void_which_binds_jwks: JSON.generate(testing.jwks(assert_key, attacker)))

      sign_in_with_void_which_binds(key: attacker)

      expect(flash[:alert]).to include("refused (kid_not_pinned)")
      expect(Account.count).to eq(0)
    end

    it "refuses an ID token for another org" do
      configure_void_which_binds!(void_which_binds_org: "ed25519:#{"0" * 64}")

      sign_in_with_void_which_binds

      expect(flash[:alert]).to include("refused (wrong_org)")
    end

    it "fetches the JWKS when none is inline, and refetches for a newly pinned key" do
      rotated = testing.key("next")
      configure_void_which_binds!(void_which_binds_jwks: nil,
                                  void_which_binds_jwks_pins: [testing.thumbprint(assert_key), testing.thumbprint(rotated)])
      jwks = stub_request(:get, "#{Vwb::ISSUER}/.well-known/jwks.json")
        .to_return({ status: 200, body: JSON.generate(testing.jwks(assert_key)) },
                   { status: 200, body: JSON.generate(testing.jwks(assert_key, rotated)) })

      sign_in_with_void_which_binds(key: rotated)

      expect(response).to redirect_to("/")
      expect(jwks).to have_been_requested.twice
    end

    it "refuses the native/API callback, which cannot check iss or hold a nonce" do
      token = mint_id_token(nonce: "n")
      post "/api/oauth/callback/void_which_binds", params: { id_token: token }

      expect(response).not_to have_http_status(:ok)
      expect(StandardId::SocialIdentity.count).to eq(0)
    end
  end

  describe "the revocation watermark" do
    it "refuses a login whose ID token was issued at or before an applied session-revoked toe" do
      toe = Time.now.to_i
      expect(push_set(mint_set(event: :session_revoked, toe: toe))).to have_http_status(:accepted)

      sign_in_with_void_which_binds(iat: toe)

      expect(flash[:alert]).to include("refused (session_revoked)")
      expect(Account.count).to eq(0)
      expect(StandardId::BrowserSession.count).to eq(0)
    end

    it "allows a login issued after the watermark" do
      toe = Time.now.to_i - 30
      push_set(mint_set(event: :session_revoked, toe: toe))

      sign_in_with_void_which_binds(iat: toe + 1)

      expect(response).to redirect_to("/")
    end

    it "re-checks under the subject's lock when the session is created" do
      account = Account.create!(email: "person@rarebit.one", name: "Person")
      session = StandardId::BrowserSession.create!(account: account, expires_at: 1.day.from_now, user_agent: "spec")
      StandardId::VoidWhichBinds::Current.pending_login = { iss: Vwb::ISSUER, sub: Vwb::SUB, iat: 1_791_000_000 }
      # A SET lands between the provider's check and the session insert.
      ActiveRecord::Base.transaction { StandardId::VoidWhichBinds::Subject.lock_for!(Vwb::ISSUER, Vwb::SUB).advance_watermark!(1_791_000_000) }

      expect { StandardId::VoidWhichBinds::Logins.record!(session) }
        .to raise_error(StandardId::InvalidGrantError, /session_revoked/)
      expect(StandardId::VoidWhichBinds::Login.count).to eq(0)
    end
  end
end
