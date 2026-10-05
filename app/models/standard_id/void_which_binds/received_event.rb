# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # A SET this relying party has applied (or acknowledged), keyed by
    # (iss, jti), so a redelivered, retried or reconciled copy is answered 202
    # and does nothing (ADR-0023, the RP's contract, step 2). Written in the
    # same transaction as the event's effects.
    class ReceivedEvent < StandardId::ApplicationRecord
      self.table_name = "standard_id_void_which_binds_received_events"

      OUTCOMES = %w[applied acknowledged].freeze

      validates :iss, :jti, :sub, :event_type, :iat, :toe, presence: true
      validates :outcome, inclusion: { in: OUTCOMES }

      # Deletes rows whose SET is older than the verifier's window: a copy of
      # such a SET is refused on its iat (iat_too_old) before the jti is ever
      # consulted, so its row no longer protects anything. Keeps a day's
      # margin past the 7-day window.
      def self.prune!(now: Time.now.to_i)
        where(iat: ...(now - SecurityEvent::MAX_AGE - 86_400)).delete_all
      end
    end
  end
end
