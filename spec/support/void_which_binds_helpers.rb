# frozen_string_literal: true

require "rack/utils"

# Configures the dummy app as a relying party of a fake moneta (the golden
# vectors' fixed issuer, client and org) and drives sign-ins and SET pushes
# through the real endpoints. Nothing here touches the network: the token
# endpoint (and, where a spec wants it, discovery and the JWKS) are WebMock
# stubs.
module VoidWhichBindsHelpers
  ISSUER = "https://moneta.example"
  CLIENT_ID = "nutripod-web"
  CLIENT_SECRET = "s3cret-client-secret"
  ORG = "ed25519:65214fc93773949e91197bf15d29c81f34538cfc0d479da9560d8bd12f2bc582"
  AUTHORIZATION_ENDPOINT = "#{ISSUER}/oidc/authorize".freeze
  TOKEN_ENDPOINT = "#{ISSUER}/oidc/token".freeze
  CALLBACK_URL = "http://www.example.com/auth/callback/void_which_binds"
  SUB = "mp:f5eacf5a96f9f986d13f20a4621d5f71"
  OTHER_SUB = "ed25519:ceaf69b0b2f5a23ba37b90951eea5f651160cc3e6f7ba8db7fa278f886d52a86"
  BROWSER = { "User-Agent" => "Mozilla/5.0 (spec)" }.freeze
  FIELDS = %i[
    void_which_binds_client_id void_which_binds_client_secret void_which_binds_issuer void_which_binds_org
    void_which_binds_jwks_pins void_which_binds_jwks void_which_binds_authorization_endpoint
    void_which_binds_token_endpoint void_which_binds_require_for_staff void_which_binds_staff_predicate
  ].freeze

  def testing
    StandardId::VoidWhichBinds::Testing
  end

  def assert_key
    testing.key("current")
  end

  def configure_void_which_binds!(**overrides)
    social = StandardId.config.social
    {
      void_which_binds_client_id: CLIENT_ID,
      void_which_binds_client_secret: CLIENT_SECRET,
      void_which_binds_issuer: ISSUER,
      void_which_binds_org: ORG,
      void_which_binds_jwks_pins: [testing.thumbprint(assert_key)],
      void_which_binds_jwks: JSON.generate(testing.jwks(assert_key)),
      void_which_binds_authorization_endpoint: AUTHORIZATION_ENDPOINT,
      void_which_binds_token_endpoint: TOKEN_ENDPOINT,
      void_which_binds_staff_predicate: ->(account) { account.staff? }
    }.merge(overrides).each { |field, value| social.public_send(:"#{field}=", value) }
  end

  def reset_void_which_binds_config!
    social = StandardId.config.social
    FIELDS.each { |field| social.delete(field) }
    StandardId.config.login_method_policy = nil
  end

  # Starts a sign-in and returns the authorization redirect's query params.
  def start_sign_in
    post "/login", params: { connection: "void_which_binds" }, headers: BROWSER
    expect(response).to have_http_status(:redirect)
    uri = URI.parse(response.location)
    expect("#{uri.scheme}://#{uri.host}#{uri.path}").to eq(AUTHORIZATION_ENDPOINT)
    Rack::Utils.parse_query(uri.query)
  end

  def mint_id_token(nonce:, sub: SUB, email: "person@rarebit.one", email_verified: true, iat: Time.now.to_i,
                    key: assert_key, **claims)
    testing.id_token(key, iss: ISSUER, sub: sub, aud: CLIENT_ID, iat: iat, nonce: nonce, org: ORG,
                          email: email, email_verified: email_verified, **claims)
  end

  # Stubs moneta's token endpoint to answer with `id_token`, checking the
  # client authentication and the PKCE verifier against the challenge sent.
  def stub_token_endpoint(id_token:, challenge:, code: "the-code")
    stub_request(:post, TOKEN_ENDPOINT).with do |request|
      form = Rack::Utils.parse_query(request.body)
      expected_auth = "Basic #{["#{CLIENT_ID}:#{CLIENT_SECRET}"].pack("m0")}"
      request.headers["Authorization"] == expected_auth &&
        form["grant_type"] == "authorization_code" && form["code"] == code &&
        form["redirect_uri"] == CALLBACK_URL &&
        StandardId::VoidWhichBinds::Pkce.s256(form["code_verifier"].to_s) == challenge
    end.to_return(
      status: 200,
      headers: { "Content-Type" => "application/json", "Cache-Control" => "no-store" },
      body: JSON.generate(id_token: id_token, access_token: "unused", token_type: "Bearer", expires_in: 300)
    )
  end

  # The whole web sign-in: /login redirect, moneta (stubbed), callback.
  # Returns the callback response. `iss` is the callback's RFC 9207 param.
  def sign_in_with_void_which_binds(iss: ISSUER, **token_claims)
    params = start_sign_in
    token = mint_id_token(nonce: params.fetch("nonce"), **token_claims)
    stub_token_endpoint(id_token: token, challenge: params.fetch("code_challenge"))
    callback = { code: "the-code", state: params.fetch("state") }
    callback[:iss] = iss if iss
    get "/auth/callback/void_which_binds", params: callback, headers: BROWSER
    response
  end

  def push_set(token, content_type: StandardId::VoidWhichBinds::SecurityEvent::CONTENT_TYPE)
    post "/auth/void_which_binds/events", params: token, headers: { "CONTENT_TYPE" => content_type }
    response
  end

  def mint_set(event:, sub: SUB, toe:, iat: Time.now.to_i, key: assert_key, reason: nil, entity: nil, **fields)
    session_revoked = event == :session_revoked
    testing.security_event(
      key,
      iss: ISSUER, aud: CLIENT_ID, iat: iat, toe: toe, sub: sub,
      event: session_revoked ? StandardId::VoidWhichBinds::SecurityEvent::SESSION_REVOKED : StandardId::VoidWhichBinds::SecurityEvent::ACCOUNT_DISABLED,
      reason: session_revoked ? (reason || "role_changed") : nil,
      initiating_entity: session_revoked ? (entity || "admin") : nil,
      **fields
    )
  end

  def signed_in?
    get "/dashboard", headers: BROWSER
    response.status == 200
  end
end

RSpec.configure do |config|
  config.include VoidWhichBindsHelpers, type: :request
  config.include VoidWhichBindsHelpers, type: :void_which_binds
end
Vwb = VoidWhichBindsHelpers
