# frozen_string_literal: true

require "spec_helper"

RSpec.describe StandardId::VoidWhichBinds::StaffPolicy, type: :void_which_binds do
  let(:staff) { Account.create!(email: "staff@rarebit.one", name: "Staff", staff: true) }
  let(:customer) { Account.create!(email: "customer@example.com", name: "Customer") }

  before do
    configure_void_which_binds!
    StandardId.config.login_method_policy = StandardId::VoidWhichBinds.staff_policy(staff_predicate: ->(account) { account.staff? })
  end

  after { reset_void_which_binds_config! }

  def enforce(account, auth_method, provider = nil, flow: :web_password)
    StandardId::LoginMethodPolicy.enforce!(account: account, auth_method: auth_method, provider: provider, flow: flow)
  end

  it "lets a staff account in only through void_which_binds" do
    expect(enforce(staff, :social, "void_which_binds", flow: :web_social)).to be(true)
  end

  it "refuses a staff account every other way, before any session exists" do
    [[:password, nil, :web_password], [:passwordless, nil, :web_passwordless], [:remember_me, nil, :web_remember_me],
     [:social, "google", :web_social], [:unspecified, nil, :web_session]].each do |method, provider, flow|
      expect { enforce(staff, method, provider, flow: flow) }
        .to raise_error(StandardId::LoginMethodDenied, StandardId::VoidWhichBinds::StaffPolicy::MESSAGE)
    end
  end

  it "re-checks a refresh with the original sign-in's method" do
    expect { enforce(staff, :password, nil, flow: :oauth_refresh_token) }.to raise_error(StandardId::LoginMethodDenied)
    expect(enforce(staff, :social, "void_which_binds", flow: :oauth_refresh_token)).to be(true)
  end

  it "leaves other accounts alone" do
    expect(enforce(customer, :password)).to be(true)
  end

  it "defers non-staff decisions to a fallback policy" do
    StandardId.config.login_method_policy = StandardId::VoidWhichBinds.staff_policy(
      staff_predicate: ->(account) { account.staff? },
      fallback: ->(auth_method:) { auth_method != :passwordless }
    )

    expect(enforce(customer, :password)).to be(true)
    expect { enforce(customer, :passwordless, flow: :web_passwordless) }.to raise_error(StandardId::LoginMethodDenied)
  end

  it "is off while void_which_binds_require_for_staff is false" do
    StandardId.config.social.void_which_binds_require_for_staff = false

    expect(enforce(staff, :password)).to be(true)
  end

  it "falls back to the configured staff predicate" do
    StandardId.config.login_method_policy = StandardId::VoidWhichBinds.staff_policy

    expect { enforce(staff, :password) }.to raise_error(StandardId::LoginMethodDenied)
  end

  it "fails closed without any staff predicate" do
    StandardId.config.social.void_which_binds_staff_predicate = nil
    StandardId.config.login_method_policy = StandardId::VoidWhichBinds.staff_policy

    expect { enforce(customer, :password) }.to raise_error(StandardId::ConfigurationError, /staff_predicate/)
  end
end

RSpec.describe "the staff-lock boot check", type: :void_which_binds do
  before { configure_void_which_binds! }
  after { reset_void_which_binds_config! }

  let(:plain) do
    Class.new(ApplicationRecord) do
      self.table_name = "accounts"
      def self.name = "PlainAccount"
    end
  end

  it "passes when the account class includes StandardId::AccountLocking" do
    expect { StandardId::VoidWhichBinds::Engine.verify_staff_lock! }.not_to raise_error
  end

  it "refuses to boot a staff lock the account class cannot perform" do
    allow(StandardId).to receive(:account_class).and_return(plain)

    expect { StandardId::VoidWhichBinds::Engine.verify_staff_lock! }
      .to raise_error(StandardId::VoidWhichBinds::ConfigurationError, /PlainAccount does not include StandardId::AccountLocking/)
  end

  it "uses the predicate held by an installed staff_policy" do
    StandardId.config.social.void_which_binds_staff_predicate = nil
    StandardId.config.login_method_policy = StandardId::VoidWhichBinds.staff_policy(staff_predicate: ->(a) { a.staff? })
    allow(StandardId).to receive(:account_class).and_return(plain)

    expect { StandardId::VoidWhichBinds::Engine.verify_staff_lock! }.to raise_error(StandardId::VoidWhichBinds::ConfigurationError)
  end

  it "is silent when no staff lock is configured" do
    StandardId.config.social.void_which_binds_require_for_staff = false
    allow(StandardId).to receive(:account_class).and_return(plain)

    expect { StandardId::VoidWhichBinds::Engine.verify_staff_lock! }.not_to raise_error
  end
end
