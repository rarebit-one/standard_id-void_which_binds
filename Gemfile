# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in standard_id-void_which_binds.gemspec
gemspec

gem "irb"
gem "ostruct"
gem "rake", "~> 13.4"

# Rails 8.1 calls `JSON.parse(json, options)` positionally in
# ActiveSupport::JSON.decode, but json 3.0 made those options keyword-only;
# standard_id's sessions table has `t.json ... default: {}` columns, which
# SQLite's copy_table deserialises. Mirrors standard_id's own pin. Drop it once
# Rails ships a json 3 compatible activesupport.
gem "json", "< 3"

group :development, :test do
  gem "rspec-rails", "~> 8.0"
  gem "sqlite3"
  gem "webmock", "~> 3.26"

  # Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
  gem "rubocop-rails-omakase", require: false
  gem "bundler-audit", require: false
  gem "simplecov", "~> 0.22", require: false
end
