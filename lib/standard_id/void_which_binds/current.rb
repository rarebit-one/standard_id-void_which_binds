# frozen_string_literal: true

require "active_support/current_attributes"

module StandardId
  module VoidWhichBinds
    # Request-scoped state between the two places one login touches: the
    # verified ID token (stashed by the provider's get_user_info) and the
    # browser session standard_id then creates (recorded by the
    # SESSION_CREATED subscriber, see Logins). Reset by the Rails executor
    # around every request and job.
    class Current < ActiveSupport::CurrentAttributes
      # { iss:, sub:, iat: } of the ID token verified in this request, until a
      # session is created from it.
      attribute :pending_login
    end
  end
end
