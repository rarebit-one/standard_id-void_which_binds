# The relying-party state ADR-0023's contract needs (standard_id-void_which_binds).
#
# - standard_id_void_which_binds_subjects: one row per (iss, sub), the
#   subject moneta's SETs and ID tokens name. `revoked_toe` is the revocation
#   watermark (#135): the latest session-revoked toe applied, raised and never
#   lowered, recorded for unknown subjects too. `last_login_iat` is the largest
#   ID-token iat a session was created from; `disabled_toe` the toe of an
#   applied account-disabled, cleared by a later login with iat > it.
# - standard_id_void_which_binds_logins: the iat of the ID token that created
#   each browser session (login_iat), so a session-revoked SET revokes exactly
#   the sessions with login_iat <= toe. The link to the account stays
#   standard_id's own (provider, sub) row in standard_id_social_identities.
# - standard_id_void_which_binds_received_events: every applied SET's jti, so a
#   redelivery is answered 202 and does nothing. Rows whose iat is older than
#   7 days may be pruned (an older SET is refused on its iat anyway).
#
# New, empty tables: nothing existing is rewritten or backfilled.
class CreateStandardIdVoidWhichBindsTables < ActiveRecord::Migration[8.0]
  include StandardId::MigrationHelpers

  def change
    create_table :standard_id_void_which_binds_subjects, id: primary_key_type do |t|
      t.string :iss, null: false
      t.string :sub, null: false
      t.bigint :revoked_toe
      t.bigint :last_login_iat
      t.bigint :disabled_toe

      t.timestamps
    end
    add_index :standard_id_void_which_binds_subjects, [:iss, :sub], unique: true,
      name: "index_standard_id_vwb_subjects_on_iss_and_sub"

    create_table :standard_id_void_which_binds_logins, id: primary_key_type do |t|
      t.references :session, type: foreign_key_type, null: false, index: { unique: true, name: "index_standard_id_vwb_logins_on_session_id" },
        foreign_key: { to_table: :standard_id_sessions, on_delete: :cascade }
      t.string :iss, null: false
      t.string :sub, null: false
      t.bigint :login_iat, null: false

      t.timestamps
    end
    add_index :standard_id_void_which_binds_logins, [:iss, :sub, :login_iat],
      name: "index_standard_id_vwb_logins_on_subject_and_login_iat"

    create_table :standard_id_void_which_binds_received_events, id: primary_key_type do |t|
      t.string :iss, null: false
      t.string :jti, null: false
      t.string :sub, null: false
      t.string :event_type, null: false
      t.bigint :iat, null: false
      t.bigint :toe, null: false
      t.string :txn
      # applied | acknowledged (applied by watermark, or an unknown subject)
      t.string :outcome, null: false

      t.timestamps
    end
    add_index :standard_id_void_which_binds_received_events, [:iss, :jti], unique: true,
      name: "index_standard_id_vwb_received_events_on_iss_and_jti"
    add_index :standard_id_void_which_binds_received_events, :iat,
      name: "index_standard_id_vwb_received_events_on_iat"
  end
end
