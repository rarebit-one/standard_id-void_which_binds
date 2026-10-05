# frozen_string_literal: true

module StandardId
  module VoidWhichBinds
    # A `login_method_policy` (standard_id >= 0.45) that refuses every way into
    # a staff account except a void_which_binds sign-in, so removing someone
    # from the org's roster removes their way into the app:
    #
    #   StandardId.configure do |c|
    #     c.login_method_policy = StandardId::VoidWhichBinds.staff_policy(
    #       staff_predicate: ->(account) { account.staff? }
    #     )
    #   end
    #
    # standard_id consults it before any session or token exists, in every
    # flow (web password, passwordless, remember-me, other social providers,
    # the OAuth grants, and each refresh with the original sign-in's method).
    # Non-staff accounts pass through to `fallback`, if given (another policy
    # with the same keyword contract), and are otherwise allowed.
    #
    # Enforced while `social.void_which_binds_require_for_staff` is true (the
    # default), so the switch can be staged without redeploying the policy.
    # `staff_predicate` falls back to `social.void_which_binds_staff_predicate`;
    # with neither, every staff decision fails closed (raises).
    class StaffPolicy
      MESSAGE = "Staff accounts must sign in with the organisation's Void-Which-Binds broker"

      # The predicate given to staff_policy (nil: the configured one is used).
      attr_reader :staff_predicate

      def initialize(staff_predicate: nil, fallback: nil)
        @staff_predicate = staff_predicate
        @fallback = fallback
      end

      def call(account:, auth_method:, provider:, request: nil, flow: nil)
        # A staff account is decided here, and only here: it is admitted by
        # void_which_binds and refused any other way. The fallback is never
        # consulted for it, so a fallback that refuses social logins cannot
        # lock staff out of the one method they are allowed.
        if Configuration.require_for_staff? && staff?(account)
          raise StandardId::LoginMethodDenied, MESSAGE unless void_which_binds?(auth_method, provider)

          return true
        end
        return true if @fallback.nil?

        context = { account:, auth_method:, provider:, request:, flow: }
        @fallback.call(**StandardId::Utils::CallableParameterFilter.filter(@fallback, context))
      end

      def staff?(account)
        predicate = @staff_predicate || Configuration.staff_predicate
        unless predicate.respond_to?(:call)
          raise StandardId::ConfigurationError, "StandardId::VoidWhichBinds.staff_policy needs a staff_predicate (or social.void_which_binds_staff_predicate)"
        end

        account.present? && predicate.call(account) ? true : false
      end

      private

      def void_which_binds?(auth_method, provider)
        auth_method&.to_sym == :social && provider.to_s == Providers::VoidWhichBinds::PROVIDER_NAME
      end
    end

    def self.staff_policy(staff_predicate: nil, fallback: nil)
      StaffPolicy.new(staff_predicate: staff_predicate, fallback: fallback)
    end
  end
end
