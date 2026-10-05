# frozen_string_literal: true

class CreateAccounts < ActiveRecord::Migration[8.0]
  def change
    create_table :accounts do |t|
      t.string :email, null: false, index: { unique: true }
      t.string :name, null: false
      t.boolean :staff, default: false, null: false

      t.boolean :locked, default: false, null: false
      t.datetime :locked_at
      t.string :lock_reason
      t.references :locked_by, polymorphic: true
      t.datetime :unlocked_at
      t.references :unlocked_by, polymorphic: true

      t.timestamps
    end
  end
end
