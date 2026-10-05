# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # One (iss, sub) subject named by moneta's ID tokens and SETs, and the
    # relying party's durable state about it (ADR-0023, the RP's contract,
    # step 3):
    #
    # - revoked_toe: the revocation watermark (#135), the latest
    #   session-revoked toe applied, for unknown subjects too; never lowered.
    # - last_login_iat: the largest ID-token iat a session was created from.
    # - disabled_toe: the toe of an applied account-disabled, until a login
    #   whose iat is greater re-enables the link.
    #
    # Keyed by the full iss_sub subject, not sub alone: another issuer's toe
    # values come from another clock and do not order against these.
    class Subject < StandardId::ApplicationRecord
      self.table_name = "standard_id_void_which_binds_subjects"

      validates :iss, :sub, presence: true

      # The row for (iss, sub), created if absent, locked FOR UPDATE for the
      # rest of the caller's transaction, so a SET and a login for the same
      # subject serialise. Must be called inside a transaction.
      def self.lock_for!(iss, sub)
        create_or_find_by!(iss: iss, sub: sub)
        lock.find_by!(iss: iss, sub: sub)
      end

      # Raises the watermark to toe if toe is greater (or none is stored).
      def advance_watermark!(toe)
        return if revoked_toe && revoked_toe >= toe

        update!(revoked_toe: toe)
      end

      # Why a session may not be created from an ID token issued at login_iat,
      # or nil: the watermark refuses login_iat <= revoked_toe (a tie
      # included), and a disabled link refuses login_iat <= disabled_toe.
      def refusal_for(login_iat)
        return "session_revoked" if revoked_toe && SecurityEvent.revokes_session?(revoked_toe, login_iat)
        return "link_disabled" if disabled_toe && !SecurityEvent.reenables_link?(disabled_toe, login_iat)

        nil
      end
    end
  end
end
