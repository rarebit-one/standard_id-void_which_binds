# frozen_string_literal: true

require "spec_helper"

# ADR-0023 #135: the watermark, the revocations and the jti commit in ONE
# transaction, before the 202. Run without the per-example transaction so a
# rollback is observable.
RSpec.describe "SET application is one transaction", type: :request do
  self.use_transactional_tests = false

  before { configure_void_which_binds! }

  after do
    reset_void_which_binds_config!
    [StandardId::VoidWhichBinds::ReceivedEvent, StandardId::VoidWhichBinds::Login, StandardId::VoidWhichBinds::Subject,
     StandardId::RefreshToken, StandardId::SocialIdentity, StandardId::Session, StandardId::Identifier, Account].each(&:delete_all)
  end

  let(:now) { Time.now.to_i }

  it "rolls back the revocation and the watermark when a later write fails, answers 500, and applies on redelivery" do
    sign_in_with_void_which_binds(iat: now - 100)
    session = StandardId::BrowserSession.find_by!(account_id: Account.find_by!(email: "person@rarebit.one").id)
    set = mint_set(event: :session_revoked, toe: now - 50)

    allow_any_instance_of(StandardId::VoidWhichBinds::ReceivedEvent).to receive(:update!)
      .and_raise(ActiveRecord::StatementInvalid, "disk full")
    push_set(set)

    expect(response).to have_http_status(:internal_server_error)
    expect(session.reload.revoked_at).to be_nil
    expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).revoked_toe).to be_nil
    expect(StandardId::VoidWhichBinds::ReceivedEvent.count).to eq(0)

    RSpec::Mocks.space.reset_all
    expect(push_set(set)).to have_http_status(:accepted)
    expect(session.reload.revoked_at).to be_present
    expect(StandardId::VoidWhichBinds::Subject.find_by!(iss: Vwb::ISSUER, sub: Vwb::SUB).revoked_toe).to eq(now - 50)
  end
end
