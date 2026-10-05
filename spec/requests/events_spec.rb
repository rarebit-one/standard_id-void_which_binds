# frozen_string_literal: true

require "spec_helper"

RSpec.describe "POST /auth/void_which_binds/events (RFC 8935 SET push)", type: :request do
  before { configure_void_which_binds! }
  after { reset_void_which_binds_config! }

  let(:now) { Time.now.to_i }

  def browser_session_for(email = "person@rarebit.one")
    StandardId::BrowserSession.find_by!(account_id: Account.find_by!(email: email).id)
  end

  def refresh_token_for(session, **attrs)
    StandardId::RefreshToken.create!(account_id: session.account_id, session_id: session.id,
                                      token_digest: SecureRandom.hex(32), expires_at: 1.day.from_now, **attrs)
  end

  def error_body
    JSON.parse(response.body)
  end

  describe "session-revoked" do
    it "revokes the subject's sessions and their refresh tokens, records the watermark, and answers 202" do
      sign_in_with_void_which_binds(iat: now - 100)
      session = browser_session_for
      token = refresh_token_for(session)
      expect(signed_in?).to be(true)

      expect(push_set(mint_set(event: :session_revoked, toe: now - 50))).to have_http_status(:accepted)
      expect(response.body).to be_empty

      expect(session.reload.revoked_at).to be_present
      expect(token.reload.revoked_at).to be_present
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).revoked_toe).to eq(now - 50)
      expect(signed_in?).to be(false)
    end

    it "spares a session created by a newer ID token (a stale event never touches a newer login)" do
      sign_in_with_void_which_binds(iat: now - 10)
      session = browser_session_for

      push_set(mint_set(event: :session_revoked, toe: now - 100))

      expect(response).to have_http_status(:accepted)
      expect(session.reload.revoked_at).to be_nil
      expect(signed_in?).to be(true)
    end

    it "revokes on a tie (login_iat == toe)" do
      sign_in_with_void_which_binds(iat: now - 10)

      push_set(mint_set(event: :session_revoked, toe: now - 10))

      expect(browser_session_for.reload.revoked_at).to be_present
    end

    it "records the watermark for a subject this app has never seen, and still answers 202" do
      push_set(mint_set(event: :session_revoked, sub: Vwb::OTHER_SUB, toe: now - 5))

      expect(response).to have_http_status(:accepted)
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::OTHER_SUB).revoked_toe).to eq(now - 5)
    end

    it "never lowers the watermark" do
      push_set(mint_set(event: :session_revoked, toe: now - 5))
      push_set(mint_set(event: :session_revoked, toe: now - 500))

      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).revoked_toe).to eq(now - 5)
    end

    it "revokes a void_which_binds refresh token that has no session (no login_iat to spare it by)" do
      sign_in_with_void_which_binds(iat: now - 10)
      session = browser_session_for
      orphan = StandardId::RefreshToken.create!(account_id: session.account_id, token_digest: SecureRandom.hex(32),
                                                expires_at: 1.day.from_now, auth_method: "social", auth_provider: "void_which_binds")
      other = StandardId::RefreshToken.create!(account_id: session.account_id, token_digest: SecureRandom.hex(32),
                                               expires_at: 1.day.from_now, auth_method: "password")

      push_set(mint_set(event: :session_revoked, toe: now - 100))

      expect(orphan.reload.revoked_at).to be_present
      expect(other.reload.revoked_at).to be_nil
    end
  end

  describe "account-disabled" do
    it "disables the link, revokes every session and refresh token of the account, and locks a staff account" do
      sign_in_with_void_which_binds(iat: now - 100)
      session = browser_session_for
      account = Account.find(session.account_id)
      account.update!(staff: true)
      password_session = StandardId::BrowserSession.create!(account: account, expires_at: 1.day.from_now, user_agent: "spec")
      token = refresh_token_for(password_session)

      push_set(mint_set(event: :account_disabled, toe: now - 50))

      expect(response).to have_http_status(:accepted)
      expect(session.reload.revoked_at).to be_present
      expect(password_session.reload.revoked_at).to be_present
      expect(token.reload.revoked_at).to be_present
      expect(account.reload).to be_locked
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).disabled_toe).to eq(now - 50)
      expect(StandardId::VoidWhichBinds::ReceivedEvent.last.outcome).to eq("applied")
    end

    it "does not lock an account the staff predicate does not match" do
      sign_in_with_void_which_binds(iat: now - 100)

      push_set(mint_set(event: :account_disabled, toe: now - 50))

      expect(Account.find_by!(email: "person@rarebit.one")).not_to be_locked
    end

    it "is acknowledged without being applied when a newer login exists (a re-add)" do
      sign_in_with_void_which_binds(iat: now - 10)
      session = browser_session_for

      push_set(mint_set(event: :account_disabled, toe: now - 100))

      expect(response).to have_http_status(:accepted)
      expect(session.reload.revoked_at).to be_nil
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).disabled_toe).to be_nil
      expect(StandardId::VoidWhichBinds::ReceivedEvent.last.outcome).to eq("acknowledged")
    end

    it "refuses a login at or before the disabled toe, and is re-enabled only by a later one" do
      sign_in_with_void_which_binds(iat: now - 100)
      push_set(mint_set(event: :account_disabled, toe: now - 50))

      sign_in_with_void_which_binds(iat: now - 50)
      expect(flash[:alert]).to include("refused (link_disabled)")

      sign_in_with_void_which_binds(iat: now - 49)
      expect(response).to redirect_to("/")
      expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).disabled_toe).to be_nil
    end
  end

  describe "deduplication" do
    it "answers a replayed jti 202 and does nothing" do
      set = mint_set(event: :session_revoked, toe: now - 50)
      push_set(set)
      sign_in_with_void_which_binds(iat: now - 40)

      expect(push_set(set)).to have_http_status(:accepted)
      expect(StandardId::VoidWhichBinds::ReceivedEvent.count).to eq(1)
      expect(StandardId::VoidWhichBinds::Receiver.receive(set).outcome).to eq(:duplicate)
    end
  end

  describe "refusals (RFC 8935 §2.3)" do
    it "answers a SET signed by an unpinned key with 400 invalid_key" do
      push_set(mint_set(event: :session_revoked, toe: now - 5, key: testing.key("attacker")))

      expect(response).to have_http_status(:bad_request)
      expect(error_body).to eq("err" => "invalid_key", "description" => "SET refused: kid_not_pinned")
    end

    it "answers another audience with 400 invalid_audience" do
      push_set(testing.security_event(assert_key, iss: Vwb::ISSUER, aud: "other-app", iat: now, toe: now - 5, sub: Vwb::SUB,
                                                  event: StandardId::VoidWhichBinds::SecurityEvent::ACCOUNT_DISABLED))

      expect(error_body["err"]).to eq("invalid_audience")
    end

    it "answers another issuer with 400 invalid_issuer" do
      push_set(testing.security_event(assert_key, iss: "https://other.example", aud: Vwb::CLIENT_ID, iat: now, toe: now - 5,
                                                  sub: Vwb::SUB, event: StandardId::VoidWhichBinds::SecurityEvent::ACCOUNT_DISABLED))

      expect(error_body["err"]).to eq("invalid_issuer")
    end

    it "answers an ID token pushed as a SET with 400 invalid_request" do
      push_set(mint_id_token(nonce: "n"))

      expect(error_body).to eq("err" => "invalid_request", "description" => "SET refused: wrong_type")
    end

    it "answers a stale SET with 400 invalid_request" do
      push_set(mint_set(event: :session_revoked, iat: now - StandardId::VoidWhichBinds::SecurityEvent::MAX_AGE - 1, toe: now - 700_000))

      expect(error_body["err"]).to eq("invalid_request")
      expect(StandardId::VoidWhichBinds::Subject.count).to eq(0)
    end

    it "answers the wrong Content-Type with 400 invalid_request" do
      push_set(mint_set(event: :session_revoked, toe: now - 5), content_type: "application/json")

      expect(error_body["err"]).to eq("invalid_request")
      expect(StandardId::VoidWhichBinds::ReceivedEvent.count).to eq(0)
    end

    it "answers its own misconfiguration with 500, which moneta retries" do
      configure_void_which_binds!(void_which_binds_issuer: nil)

      push_set(mint_set(event: :session_revoked, toe: now - 5))

      expect(response).to have_http_status(:internal_server_error)
    end
  end
end
