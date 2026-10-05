# frozen_string_literal: true

StandardId.configure do |c|
  c.account_class_name = "Account"
  # The dummy runs standard_id's migrations straight from the gem.
  c.missing_migrations = :ignore
end
