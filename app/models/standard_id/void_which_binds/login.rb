# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # The ID token behind one browser session: its subject and its iat
    # (login_iat), so a session-revoked SET revokes exactly the sessions with
    # login_iat <= toe and spares newer ones.
    class Login < StandardId::ApplicationRecord
      self.table_name = "standard_id_void_which_binds_logins"

      validates :session_id, :iss, :sub, :login_iat, presence: true
    end
  end
end
