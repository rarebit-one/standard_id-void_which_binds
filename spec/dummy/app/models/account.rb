# frozen_string_literal: true

class Account < ApplicationRecord
  include StandardId::AccountAssociations
  include StandardId::AccountLocking

  validates :email, presence: true
  validates :name, presence: true
end
