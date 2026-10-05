# frozen_string_literal: true

require_relative "lib/standard_id/void_which_binds/version"

Gem::Specification.new do |spec|
  spec.name = "standard_id-void_which_binds"
  spec.version = StandardId::VoidWhichBinds::VERSION
  spec.authors = ["Jaryl Sim"]
  spec.email   = ["code@jaryl.dev"]

  spec.summary = "Void-Which-Binds (moneta) sign-in and SET deprovisioning for the StandardId engine."
  spec.description = "StandardId provider plugin for an organisation's Void-Which-Binds broker (moneta), per ADR-0023: " \
                     "OIDC authorization code + PKCE with Ed25519 ID tokens verified against pinned keys, a staff " \
                     "login-method policy, and an RFC 8935 Security Event Token receiver that revokes sessions by " \
                     "watermark."
  spec.homepage = "https://github.com/rarebit-one/standard_id-void_which_binds"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 4.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"

  # Allow-list, not a reject-list: only these paths ship (matches the rest of
  # the standard_* family; a reject-list fails OPEN).
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["lib/**/*", "app/**/*", "config/**/*", "db/**/*", "LICENSE", "Rakefile", "README.md", "CHANGELOG.md"]
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "activesupport", ">= 8.1"
  spec.add_dependency "rails", ">= 8.1"
  # `allow_duplicate_key: false`, which the strict JSON parser relies on
  # (checked at boot, see Jose.assert_strict_json!).
  spec.add_dependency "json", ">= 2.13"
  # The FLOOR is 0.46: this plugin relies on core-managed PKCE
  # (Providers::Base.supports_pkce?) and the `callback_iss:` / `code_verifier:`
  # kwargs to get_user_info, new in 0.46, as well as on 0.45's
  # Providers::Base#trusted_for_linking?, `config.login_method_policy` and the
  # refresh-token auth lineage. The CEILING stays loose (`~> 0.46` = `< 1.0`); compatibility above
  # the floor is enforced by CI's `compat` job against the latest published
  # standard_id (see standard_id-google's gemspec for why a narrow cap failed).
  spec.add_dependency "standard_id", "~> 0.46"
end
