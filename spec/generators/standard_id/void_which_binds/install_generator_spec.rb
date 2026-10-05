# frozen_string_literal: true

require "spec_helper"
require "fileutils"
require "stringio"
require "tmpdir"
require "rails/generators"
require "generators/standard_id/void_which_binds/install/install_generator"

RSpec.describe StandardId::VoidWhichBinds::Generators::InstallGenerator do
  let(:destination_root) { @destination_root }
  let(:initializer_path) { File.join(destination_root, "config/initializers/standard_id_void_which_binds.rb") }
  let(:routes_path) { File.join(destination_root, "config/routes.rb") }

  before do
    @destination_root = Dir.mktmpdir("standard_id_void_which_binds_generator")
    FileUtils.mkdir_p(File.join(destination_root, "config/initializers"))
    FileUtils.mkdir_p(File.join(destination_root, "db/migrate"))
    File.write(routes_path, "Rails.application.routes.draw do\nend\n")
  end

  after { FileUtils.rm_rf(destination_root) }

  def run_generator(options = {})
    generator = described_class.new([], options)
    generator.destination_root = destination_root
    original = $stdout
    $stdout = StringIO.new
    generator.invoke_all
  ensure
    $stdout = original
  end

  it "is registered under the standard_id:void_which_binds:install namespace" do
    expect(described_class.namespace).to eq("standard_id:void_which_binds:install")
  end

  it "writes the initializer with every required field in the social scope" do
    run_generator
    content = File.read(initializer_path)

    %w[client_id client_secret issuer org jwks_pins].each do |field|
      expect(content).to include("config.social.void_which_binds_#{field}")
      expect(content).to include("ENV.fetch(\"VOID_WHICH_BINDS_#{field.upcase}\"")
    end
  end

  it "copies the migration once" do
    run_generator
    run_generator

    migrations = Dir[File.join(destination_root, "db/migrate/*_create_standard_id_void_which_binds_tables*.rb")]
    expect(migrations.size).to eq(1)
    expect(File.read(migrations.first)).to include("standard_id_void_which_binds_subjects")
  end

  it "mounts the SET endpoint once" do
    run_generator
    run_generator

    expect(File.read(routes_path).scan("StandardId::VoidWhichBinds::Engine").size).to eq(1)
  end

  it "skips an existing initializer unless forced" do
    File.write(initializer_path, "# mine\n")
    run_generator
    expect(File.read(initializer_path)).to eq("# mine\n")

    run_generator(force: true)
    expect(File.read(initializer_path)).to include("void_which_binds_client_id")
  end
end
