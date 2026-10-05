# frozen_string_literal: true

class DashboardController < ApplicationController
  include StandardId::WebAuthentication

  def show
    if current_account
      render plain: "signed in as #{current_account.email}"
    else
      render plain: "anonymous", status: :unauthorized
    end
  end
end
