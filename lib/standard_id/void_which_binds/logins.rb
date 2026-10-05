# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # Session creation under the revocation watermark (ADR-0023, the RP's
    # contract, step 3, amended by #135).
    #
    # The provider calls check! as soon as the ID token verifies, so a stale
    # token is refused before any account is touched. standard_id then creates
    # the browser session; its SESSION_CREATED event runs record!, which, in
    # one transaction holding the subject's row lock, checks again (a SET may
    # have landed in between) and records the session's login_iat. A SET
    # applied before that lock is taken is seen by the second check; one
    # applied after it finds the login row and revokes the session. Either
    # way no session outlives a revocation moneta has been told is applied.
    module Logins
      module_function

      # Raises Refusal ("session_revoked" or "link_disabled") when a session
      # may not be created from an ID token issued at login_iat for (iss, sub).
      def check!(iss:, sub:, login_iat:)
        refusal = Subject.find_by(iss: iss, sub: sub)&.refusal_for(login_iat)
        raise Refusal, refusal if refusal

        true
      end

      # The SESSION_CREATED subscriber. Records the pending login (the ID
      # token this request verified) against the session just created from
      # it, or refuses the session by raising StandardId::InvalidGrantError,
      # which standard_id's callback turns into a revoked session and a
      # redirect back to the login page.
      def record!(session)
        pending = Current.pending_login
        return if pending.nil? || session.nil? || session.id.nil?

        Current.pending_login = nil
        ActiveRecord::Base.transaction do
          subject = Subject.lock_for!(pending[:iss], pending[:sub])
          refusal = subject.refusal_for(pending[:iat])
          if refusal
            raise StandardId::InvalidGrantError, "Void-Which-Binds sign-in refused (#{refusal})"
          end

          Login.create!(session_id: session.id, iss: pending[:iss], sub: pending[:sub], login_iat: pending[:iat])
          attributes = {}
          attributes[:last_login_iat] = pending[:iat] if subject.last_login_iat.nil? || pending[:iat] > subject.last_login_iat
          attributes[:disabled_toe] = nil if subject.disabled_toe
          subject.update!(attributes) if attributes.any?
        end
      end
    end
  end
end
