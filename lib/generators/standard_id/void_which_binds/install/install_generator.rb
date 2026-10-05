# frozen_string_literal: true

require "rails/generators"

module StandardId
  module VoidWhichBinds
    module Generators
      # Installs Void-Which-Binds sign-in in a host Rails app:
      #
      # - config/initializers/standard_id_void_which_binds.rb, the
      #   social.void_which_binds_* fields wired to ENV (a separate file from
      #   standard_id.rb, so removing the provider is deleting one file);
      # - the migration for the watermark, login and jti tables;
      # - the SET push endpoint's mount in config/routes.rb.
      #
      # Idempotent: an existing initializer, migration or mount is skipped.
      class InstallGenerator < Rails::Generators::Base
        source_root File.expand_path("templates", __dir__)

        INITIALIZER_PATH = "config/initializers/standard_id_void_which_binds.rb"
        MIGRATION_NAME = "create_standard_id_void_which_binds_tables"
        MOUNT = %(mount StandardId::VoidWhichBinds::Engine => "/auth/void_which_binds")

        desc "Installs StandardId Void-Which-Binds: initializer, migration and the SET endpoint mount."

        class_option :skip_initializer, type: :boolean, default: false, desc: "Do not write #{INITIALIZER_PATH}"
        class_option :skip_migration, type: :boolean, default: false, desc: "Do not copy the migration"
        class_option :skip_route, type: :boolean, default: false, desc: "Do not mount the SET endpoint"
        class_option :force, type: :boolean, default: false, desc: "Overwrite #{INITIALIZER_PATH} if it already exists"

        def copy_initializer
          return say_status("skip", "#{INITIALIZER_PATH} (--skip-initializer)", :yellow) if options[:skip_initializer]

          if File.exist?(File.join(destination_root, INITIALIZER_PATH)) && !options[:force]
            return say_status("identical", "#{INITIALIZER_PATH} (already exists; pass --force to overwrite)", :blue)
          end

          template "initializer.rb.erb", INITIALIZER_PATH, force: options[:force]
        end

        def copy_migration
          return say_status("skip", "migration (--skip-migration)", :yellow) if options[:skip_migration]

          existing = Dir[File.join(destination_root, "db/migrate/*_#{MIGRATION_NAME}*.rb")]
          return say_status("identical", "db/migrate/*_#{MIGRATION_NAME}.rb (already installed)", :blue) if existing.any?

          source = File.expand_path("../../../../../db/migrate/20261005000000_#{MIGRATION_NAME}.rb", __dir__)
          timestamp = Time.now.utc.strftime("%Y%m%d%H%M%S")
          copy_file source, "db/migrate/#{timestamp}_#{MIGRATION_NAME}.standard_id_void_which_binds.rb"
        end

        def mount_engine
          return say_status("skip", "route (--skip-route)", :yellow) if options[:skip_route]

          routes = File.join(destination_root, "config/routes.rb")
          return say_status("skip", "config/routes.rb not found; add: #{MOUNT}", :yellow) unless File.exist?(routes)
          return say_status("identical", "SET endpoint mount (already in config/routes.rb)", :blue) if File.read(routes).include?("StandardId::VoidWhichBinds::Engine")

          route MOUNT
        end

        def print_hints
          say ""
          say "=" * 79
          say "StandardId Void-Which-Binds installed. Run bin/rails db:migrate, then set:"
          say ""
          say "  VOID_WHICH_BINDS_CLIENT_ID      this app's client_id in the org's moneta"
          say "  VOID_WHICH_BINDS_CLIENT_SECRET  its client secret (client_secret_basic)"
          say "  VOID_WHICH_BINDS_ISSUER         moneta's https origin, no trailing slash"
          say "  VOID_WHICH_BINDS_ORG            the org id, ed25519:<64 hex>"
          say "  VOID_WHICH_BINDS_JWKS_PINS      pinned assert-key thumbprints, comma-separated"
          say ""
          say "Register with moneta: redirect URI <origin>/auth/callback/void_which_binds"
          say "and SET push endpoint <origin>/auth/void_which_binds/events, for EVERY origin."
          say "=" * 79
          say ""
        end
      end
    end
  end
end
