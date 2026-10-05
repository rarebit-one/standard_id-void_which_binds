# frozen_string_literal: true

require "spec_helper"

# Replays every ADR-0023 OIDC golden vector from void-which-binds-go
# (spec/vectors/oidc, pinned by VOID_WHICH_BINDS_GO_REF): the JWK and JWKS
# bytes, every ID-token verdict, the pin rotation, PKCE and the discovery
# document. Tokens are re-signed byte for byte from their header, payload and
# seed, and the accepted ones re-minted from their verified claims.
RSpec.describe "void-which-binds-go OIDC vectors" do
  jose = StandardId::VoidWhichBinds::Jose
  id_token = StandardId::VoidWhichBinds::IdToken
  files = VectorHelpers.files("oidc")

  it "covers all 26 files" do
    expect(files.size).to eq(26)
  end

  files.each do |path|
    vector = VectorHelpers.load(path)

    describe vector["name"] do
      it "is named after its file" do
        expect(vector["name"]).to eq(File.basename(path, ".json"))
      end

      case vector["kind"]
      when "jwk"
        it "reproduces RFC 8037 Appendix A.3's thumbprint" do
          expect(jose.thumbprint(vector["rfc8037_jwk"])).to eq(vector["rfc8037_thumbprint"])
          expect(vector["rfc8037_thumbprint"]).to eq("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
        end

        it "derives each key's JWK and kid from its seed, in rendering order" do
          vector["keys"].each do |label, entry|
            key = VectorHelpers.key_for(vector, label)
            jwk = jose.public_jwk(key.raw_public_key)
            expect(jose.marshal(jwk)).to eq(jose.marshal(entry["jwk"])), label
            expect(jose.thumbprint(jwk)).to eq(entry["jwk"]["kid"]), label
          end
        end

        it "renders the JWKS bytes, current alone and current plus next" do
          current = jose.public_jwk(VectorHelpers.key_for(vector, "current").raw_public_key)
          following = jose.public_jwk(VectorHelpers.key_for(vector, "next").raw_public_key)
          expect(jose.marshal({ "keys" => [current] })).to eq(vector["jwks_current"])
          expect(jose.marshal({ "keys" => [current, following] })).to eq(vector["jwks_rotation"])
          expect(jose.parse_jwks(vector["jwks_rotation"]).map { |k| jose.marshal(k) }).to eq([jose.marshal(current), jose.marshal(following)])
        end
      when "idtoken"
        it "carries the token's decoded header and payload" do
          expect(VectorHelpers.decoded_parts(vector["token"])).to eq([vector["header"], vector["payload"]])
        end

        unless vector["tampered"]
          it "re-signs byte for byte from header, payload and the signer's seed" do
            key = VectorHelpers.key_for(vector, vector["signer"])
            expect(VectorHelpers.raw_sign(key, vector["header"], vector["payload"])).to eq(vector["token"])
          end
        end

        it "verifies to #{vector["verdict"]}" do
          expectation = VectorHelpers.id_expect(vector["expect"], VectorHelpers.pins(vector))
          expect(VectorHelpers.verdict { id_token.verify(vector["token"], expectation) }).to eq(vector["verdict"])
        end

        if vector["verdict"] == "ok"
          it "re-mints the verified claims to the same token" do
            expectation = VectorHelpers.id_expect(vector["expect"], VectorHelpers.pins(vector))
            claims = id_token.verify(vector["token"], expectation)
            expect(id_token.sign(VectorHelpers.key_for(vector, vector["signer"]), claims)).to eq(vector["token"])
          end
        end
      when "pin-rotation"
        vector["rows"].each_with_index do |row, i|
          it "row #{i}: a #{row["token"]}-signed token under #{row["pins"].size} pin(s) is #{row["verdict"]}" do
            expectation = VectorHelpers.id_expect(vector["expect"], VectorHelpers.pins(vector, row["pins"]))
            got = VectorHelpers.verdict { id_token.verify(vector["tokens"].fetch(row["token"]), expectation) }
            expect(got).to eq(row["verdict"])
          end
        end
      when "pkce"
        pkce = StandardId::VoidWhichBinds::Pkce
        vector["pkce"].each do |row|
          it "#{row["check"]}: #{row["note"]} (#{row["verdict"]})" do
            got = VectorHelpers.verdict do
              if row["check"] == "challenge"
                pkce.check_challenge!(row["method"], row["challenge"])
              else
                pkce.verify_verifier!(row["challenge"], row["verifier"])
              end
            end
            expect(got).to eq(row["verdict"])
          end
        end
      when "discovery"
        it "renders the exact document" do
          document = StandardId::VoidWhichBinds::Discovery.render(vector["issuer"], vector["authorization_endpoint"], vector["token_endpoint"])
          expect(document).to eq(vector["document"])
        end
      else
        it "is a kind this suite replays" do
          raise "unknown vector kind #{vector["kind"].inspect}"
        end
      end
    end
  end
end
