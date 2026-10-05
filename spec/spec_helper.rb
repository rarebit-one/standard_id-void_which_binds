# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  enable_coverage :branch
  add_filter "/spec/"
end

ENV["RAILS_ENV"] = "test"

# A fresh SQLite database for every run, built from the migrations a host
# installs: the dummy's accounts table, standard_id's own, and this gem's.
dummy_root = File.expand_path("dummy", __dir__)
FileUtils.mkdir_p(File.join(dummy_root, "tmp"))
Dir[File.join(dummy_root, "tmp", "test.sqlite3*")].each { |f| File.delete(f) }

require_relative "dummy/config/environment"
require "rspec/rails"
require "webmock/rspec"
require "standard_id/void_which_binds/testing"

ActiveRecord::Migration.verbose = false
ActiveRecord::MigrationContext.new([
  File.join(dummy_root, "db", "migrate"),
  File.join(Gem.loaded_specs.fetch("standard_id").full_gem_path, "db", "migrate"),
  File.expand_path("../db/migrate", __dir__)
]).migrate
ActiveRecord::Base.descendants.each(&:reset_column_information)

Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |f| require f }

WebMock.disable_net_connect!

RSpec.configure do |config|
  config.example_status_persistence_file_path = ".rspec_status"
  config.disable_monkey_patching!
  config.use_transactional_fixtures = true
  config.filter_rails_from_backtrace!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before do
    StandardId::VoidWhichBinds::Broker.reset!
    StandardId::VoidWhichBinds::Current.reset
  end
end
