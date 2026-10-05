# frozen_string_literal: true

require "spec_helper"

# Replays every ADR-0023 Security Event Token golden vector from
# void-which-binds-go (spec/vectors/secevent, pinned by
# VOID_WHICH_BINDS_GO_REF): each SET verdict and its RFC 8935 answer, the
# ordering rules, the revocation watermark (#135) against this gem's own
# database-backed store, and the delivery classification.
RSpec.describe "void-which-binds-go SET vectors" do
  set_module = StandardId::VoidWhichBinds::SecurityEvent
  files = VectorHelpers.files("secevent")

  it "covers all 25 files" do
    expect(files.size).to eq(25)
  end

  files.each do |path|
    vector = VectorHelpers.load(path)

    describe vector["name"] do
      it "is named after its file" do
        expect(vector["name"]).to eq(File.basename(path, ".json"))
      end

      case vector["kind"]
      when "token"
        it "carries the token's decoded header and payload" do
          expect(VectorHelpers.decoded_parts(vector["token"])).to eq([vector["header"], vector["payload"]])
        end

        unless vector["tampered"]
          it "re-signs byte for byte from header, payload and the signer's seed" do
            key = VectorHelpers.key_for(vector, vector["signer"])
            expect(VectorHelpers.raw_sign(key, vector["header"], vector["payload"])).to eq(vector["token"])
          end
        end

        if vector["verifier"] == "idtoken"
          it "is refused by the ID-token verifier as #{vector["verdict"]}" do
            expectation = VectorHelpers.id_expect(vector["expect_idtoken"], VectorHelpers.pins(vector))
            got = VectorHelpers.verdict { StandardId::VoidWhichBinds::IdToken.verify(vector["token"], expectation) }
            expect(got).to eq(vector["verdict"])
          end
        else
          it "verifies to #{vector["verdict"]}, answered #{vector["rfc8935_err"].empty? ? "202" : "400 #{vector["rfc8935_err"]}"}" do
            expectation = VectorHelpers.set_expect(vector["expect_set"], VectorHelpers.pins(vector))
            error = nil
            begin
              set_module.verify(vector["token"], expectation)
            rescue StandardId::VoidWhichBinds::Refusal => e
              error = e
            end
            expect(error ? error.verdict : "ok").to eq(vector["verdict"])

            status, code = set_module.response(error)
            if vector["rfc8935_err"].empty?
              expect([status, code]).to eq([202, ""])
            else
              expect([status, code]).to eq([400, vector["rfc8935_err"]])
            end
          end

          if vector["verdict"] == "ok"
            it "re-mints the verified SET to the same token" do
              expectation = VectorHelpers.set_expect(vector["expect_set"], VectorHelpers.pins(vector))
              set = set_module.verify(vector["token"], expectation)
              expect(set_module.sign(VectorHelpers.key_for(vector, vector["signer"]), set)).to eq(vector["token"])
            end
          end
        end
      when "ordering"
        vector["ordering"].each_with_index do |row, i|
          it "row #{i}: #{row["note"]}" do
            got =
              case row["rule"]
              when "revokes_session" then set_module.revokes_session?(row["toe"], row["login_iat"])
              when "disables_link" then set_module.disables_link?(row["toe"], row["last_login_iat"])
              when "reenables_link" then set_module.reenables_link?(row["toe"], row["login_iat"])
              else raise "unknown rule #{row["rule"]}"
              end
            expect(got).to eq(row["expect"])
          end
        end
      when "watermark"
        it "runs every step in order against one empty store keyed by (iss, sub)" do
          subject_model = StandardId::VoidWhichBinds::Subject
          expect(subject_model.count).to eq(0)

          vector["watermark"].each_with_index do |step, i|
            case step["op"]
            when "advance"
              ActiveRecord::Base.transaction do
                subject_model.lock_for!(step["iss"], step["sub"]).advance_watermark!(step["toe"])
              end
            when "check"
              got = VectorHelpers.verdict do
                StandardId::VoidWhichBinds::Logins.check!(iss: step["iss"], sub: step["sub"], login_iat: step["login_iat"])
              end
              expect(got).to eq(step["verdict"]), "step #{i}: #{step["note"]}"
            else
              raise "unknown op #{step["op"]}"
            end
          end
        end
      when "delivery"
        vector["delivery"].each do |row|
          it "classifies #{row["status"]} #{row["body"].inspect} as #{row["outcome"]}" do
            expect(set_module.classify(row["status"], row["body"]).to_s).to eq(row["outcome"])
          end
        end

        it "maps each RFC 8935 code to retryable or terminal" do
          vector["retryable"].each do |code, retryable|
            expect(set_module.retryable?(code)).to eq(retryable), code
          end
        end
      else
        it "is a kind this suite replays" do
          raise "unknown vector kind #{vector["kind"].inspect}"
        end
      end
    end
  end
end
