# frozen_string_literal: true

require "spec_helper"

# A host OAuth client authorized from a Void-Which-Binds browser session, on
# an app without a session_type_resolver: the refresh token it gets carries no
# session (and so no login_iat), only the void_which_binds lineage.
RSpec.describe "OAuth authorization from a Void-Which-Binds sign-in", type: :request do
  before { configure_void_which_binds! }
  after { reset_void_which_binds_config! }

  let(:now) { Time.now.to_i }
  let(:redirect_uri) { "https://client.example/callback" }
  let(:code_verifier) { "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }

  def authorize_client!(account)
    client = StandardId::ClientApplication.create!(
      owner: account, name: "Client", redirect_uris: redirect_uri, scopes: "openid",
      grant_types: "authorization_code refresh_token", response_types: "code",
      client_type: "public", require_pkce: true, code_challenge_methods: "S256", require_consent: false
    )
    get "/api/authorize", headers: Vwb::BROWSER, params: {
      response_type: "code", client_id: client.client_id, redirect_uri: redirect_uri, scope: "openid",
      state: "client-state", code_challenge: StandardId::VoidWhichBinds::Pkce.s256(code_verifier),
      code_challenge_method: "S256"
    }
    expect(response).to have_http_status(:found)
    code = Rack::Utils.parse_query(URI.parse(response.location).query).fetch("code")

    post "/api/oauth/token", as: :json, headers: Vwb::BROWSER, params: {
      grant_type: "authorization_code", client_id: client.client_id, code: code,
      redirect_uri: redirect_uri, code_verifier: code_verifier
    }
    expect(response).to have_http_status(:ok), -> { response.body }
    jti = StandardId::JwtService.decode(JSON.parse(response.body).fetch("refresh_token"))[:jti]
    StandardId::RefreshToken.find_by_jti(jti)
  end

  it "has already recorded the login it was authorized from, so a delayed account-disabled leaves it alone" do
    sign_in_with_void_which_binds(iat: now - 10)
    account = Account.find_by!(email: "person@rarebit.one")
    token = authorize_client!(account)
    expect([token.session_id, token.auth_provider]).to eq([nil, "void_which_binds"])
    expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).last_login_iat).to eq(now - 10)

    # Disabled at toe, re-added, signed in again at now - 10; the SET arrives late.
    push_set(mint_set(event: :account_disabled, toe: now - 50))

    expect(response).to have_http_status(:accepted)
    expect(StandardId::VoidWhichBinds::ReceivedEvent.last.outcome).not_to eq("applied")
    expect(token.reload.revoked_at).to be_nil
    expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).disabled_toe).to be_nil
  end

  it "is revoked by an account-disabled issued at or after that login" do
    sign_in_with_void_which_binds(iat: now - 10)
    token = authorize_client!(Account.find_by!(email: "person@rarebit.one"))

    push_set(mint_set(event: :account_disabled, toe: now - 10))

    expect(response).to have_http_status(:accepted)
    expect(token.reload.revoked_at).to be_present
  end
end
