# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # The RFC 8935 push receiver's logic (ADR-0023, "The RP's contract"):
    # verify the SET, deduplicate its jti, apply it by watermark, and only then
    # let the endpoint answer 202. Everything step 3 writes (the jti, the
    # watermark, the revocations, the disabled link, the staff lock) commits in
    # ONE transaction before the answer, so a crash or rollback after a 202
    # can never lose a revocation moneta now treats as acknowledged.
    module Receiver
      PROVIDER = Providers::VoidWhichBinds::PROVIDER_NAME
      REVOCATION_REASON_PREFIX = "void_which_binds."

      Result = Struct.new(:outcome, :set, keyword_init: true) do
        # :applied, :acknowledged (stale, or nothing to apply) or :duplicate.
        def applied? = outcome == :applied
      end

      module_function

      # Verifies `token` against this app's configuration.
      # @raise [Refusal, ExpectError, ConfigurationError]
      def verify(token, now: Time.now.to_i)
        Broker.with_pins do |pins|
          SecurityEvent.verify(token, SecurityEvent::Expect.new(
            issuer: Configuration.issuer,
            audience: Configuration.client_id.to_s,
            pins: pins,
            now: now,
            max_age: SecurityEvent::MAX_AGE
          ))
        end
      end

      # Verifies and applies `token`; returns a Result. Raises on a refusal
      # (see SecurityEvent.response for the RFC 8935 answer) and on a database
      # error (answered 500, retried by moneta).
      def receive(token, now: Time.now.to_i)
        apply!(verify(token, now: now))
      end

      # Applies a verified SET in one transaction.
      def apply!(set)
        ActiveRecord::Base.transaction do
          event = record_jti(set)
          next Result.new(outcome: :duplicate, set: set) if event.nil?

          subject = Subject.lock_for!(set.iss, set.sub)
          applied =
            if set.session_revoked?
              apply_session_revoked(subject, set)
            else
              apply_account_disabled(subject, set)
            end
          event.update!(outcome: applied ? "applied" : "acknowledged")
          Result.new(outcome: applied ? :applied : :acknowledged, set: set)
        end
      end

      # The jti row, or nil when this (iss, jti) was already received. Its own
      # savepoint, so a losing concurrent insert does not abort the transaction.
      def record_jti(set)
        return nil if ReceivedEvent.exists?(iss: set.iss, jti: set.jti)

        ReceivedEvent.transaction(requires_new: true) do
          ReceivedEvent.create!(iss: set.iss, jti: set.jti, sub: set.sub, event_type: set.event, iat: set.iat,
                                toe: set.toe, txn: set.txn, outcome: "acknowledged")
        end
      rescue ActiveRecord::RecordNotUnique
        nil
      end

      # session-revoked: raise the subject's watermark (for an unknown subject
      # too) and revoke the sessions whose ID token was issued at or before
      # toe (newer ones are untouched), cascading to their refresh tokens.
      def apply_session_revoked(subject, set)
        subject.advance_watermark!(set.toe)

        session_ids = Login.where(iss: set.iss, sub: set.sub).where(login_iat: ..set.toe).pluck(:session_id)
        revoke_sessions(StandardId::Session.where(id: session_ids, revoked_at: nil), reason(set))
        revoke_sessionless_refresh_tokens(linked_account_ids(set.sub))
        true
      end

      # account-disabled: applies only when toe >= the subject's newest login
      # (otherwise a newer login exists, which moneta minted only after a
      # re-add, and the event is acknowledged without being applied). Then the
      # link is disabled at toe, every session and refresh token of the linked
      # account is revoked, and a staff account is locked.
      def apply_account_disabled(subject, set)
        return false unless SecurityEvent.disables_link?(set.toe, subject.last_login_iat || 0)

        subject.update!(disabled_toe: set.toe) if subject.disabled_toe.nil? || set.toe > subject.disabled_toe
        linked_account_ids(set.sub).each do |account_id|
          StandardId::Session.revoke_all_for!(account_id, reason: reason(set))
          StandardId::RefreshToken.where(account_id: account_id, revoked_at: nil).update_all(revoked_at: Time.current)
          lock_staff_account(account_id)
        end
        true
      end

      def revoke_sessions(scope, reason)
        sessions = scope.to_a
        sessions.group_by(&:account_id).each_value do |group|
          StandardId::Session.revoke_sessions!(group, reason: reason)
        end
      end

      # Refresh tokens minted from a void_which_binds login that carry no
      # session (a host OAuth flow without a session_type_resolver) have no
      # login_iat to compare, so they are revoked: failing closed costs that
      # client one re-authorization.
      def revoke_sessionless_refresh_tokens(account_ids)
        return 0 if account_ids.empty?
        return 0 unless StandardId::RefreshToken.column_names.include?("auth_provider")

        StandardId::RefreshToken
          .where(account_id: account_ids, session_id: nil, auth_provider: PROVIDER, revoked_at: nil)
          .update_all(revoked_at: Time.current)
      end

      # Accounts linked to this sub through standard_id's (provider, sub) row.
      # One issuer per app in v1: standard_id keys the link by provider name.
      def linked_account_ids(sub)
        return [] unless StandardId::SocialIdentity.available?

        StandardId::SocialIdentity.where(provider: PROVIDER, subject: sub).distinct.pluck(:account_id)
      end

      # Locks a staff account through StandardId::AccountLocking's
      # `lock!(reason:)`. Every Active Record model also has the unrelated
      # pessimistic-locking `lock!`, so the capability is checked by the
      # concern, never by respond_to?. An account class without the concern
      # cannot be locked: the revocations still commit (they are what ends the
      # person's access, and failing them would make every retry a 500), and
      # the gap is logged and reported here and refused at boot
      # (Receiver.staff_lock_configuration_error).
      def lock_staff_account(account_id)
        predicate = staff_lock_predicate
        return if predicate.nil?

        account = StandardId.account_class.find_by(id: account_id)
        return if account.nil? || !predicate.call(account)

        unless account_locking?(account.class)
          report_lock_unsupported(account.class)
          return
        end

        account.lock!(reason: "#{REVOCATION_REASON_PREFIX}account_disabled")
      end

      # The staff predicate the lock applies, or nil when the staff lock is
      # off: the configured one, else the one the installed staff_policy holds.
      def staff_lock_predicate
        return nil unless Configuration.require_for_staff?

        predicate = Configuration.staff_predicate
        policy = StandardId.config.login_method_policy
        predicate ||= policy.staff_predicate if policy.is_a?(StaffPolicy)
        predicate.respond_to?(:call) ? predicate : nil
      end

      def account_locking?(klass)
        klass.is_a?(Class) && klass <= StandardId::AccountLocking
      end

      # Why the staff lock cannot work with this app's account class, or nil.
      def staff_lock_configuration_error
        return nil if staff_lock_predicate.nil?

        klass = StandardId.account_class
        return nil if account_locking?(klass)

        "a staff lock is configured (void_which_binds_require_for_staff with a staff predicate) but " \
          "#{klass.name} does not include StandardId::AccountLocking, so a roster removal cannot lock a staff account"
      end

      def report_lock_unsupported(klass)
        message = "[StandardId::VoidWhichBinds] staff account not locked: #{klass.name} does not include StandardId::AccountLocking"
        StandardId.logger&.error(message)
        Rails.error.report(ConfigurationError.new(message), handled: true, source: "standard_id-void_which_binds")
      end

      def reason(set)
        cause = set.session_revoked? ? set.reason : "account_disabled"
        "#{REVOCATION_REASON_PREFIX}#{cause}"
      end
    end
  end
end
