# frozen_string_literal: true

require "active_support/current_attributes"

module StandardId
  module VoidWhichBinds
    # Request-scoped state between the three places one login touches: the
    # callback's RFC 9207 `iss` (captured before the provider runs), the
    # verified ID token (stashed by the provider's get_user_info), and the
    # browser session standard_id then creates (recorded by the
    # SESSION_CREATED subscriber, see Logins). Reset by the Rails executor
    # around every request and job.
    class Current < ActiveSupport::CurrentAttributes
      # Whether the web callback ran the iss capture (false: the provider was
      # called from a flow that cannot check iss, which is refused).
      attribute :callback_checked
      # The callback's `iss` parameter (RFC 9207).
      attribute :callback_iss
      # { iss:, sub:, iat: } of the ID token verified in this request, until a
      # session is created from it.
      attribute :pending_login
    end
  end
end
