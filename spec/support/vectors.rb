# frozen_string_literal: true

require "json"

# Loads void-which-binds-go's ADR-0023 golden vectors (copied verbatim under
# spec/vectors/, pinned by spec/vectors/VOID_WHICH_BINDS_GO_REF).
module VectorHelpers
  VECTORS_DIR = File.expand_path("../vectors", __dir__)

  module_function

  def files(suite)
    Dir[File.join(VECTORS_DIR, suite, "*.json")].sort
  end

  def load(path)
    JSON.parse(File.read(path))
  end

  def key_for(vector, label)
    seed = vector.fetch("keys").fetch(label).fetch("seed")
    StandardId::VoidWhichBinds::Testing.seed_key([seed].pack("H*"))
  end

  # The verdict a verifier reaches, spelled as the vectors spell it.
  def verdict
    yield
    "ok"
  rescue StandardId::VoidWhichBinds::Refusal => e
    e.verdict
  rescue StandardId::VoidWhichBinds::ExpectError
    "expect"
  end

  def pins(vector, thumbprints = vector["pins"])
    StandardId::VoidWhichBinds::Jose::Pins.new(JSON.generate(vector.fetch("jwks")), thumbprints)
  end

  def id_expect(raw, pins)
    StandardId::VoidWhichBinds::IdToken::Expect.new(
      issuer: raw["issuer"], client_id: raw["client_id"], org: raw["org"], nonce: raw["nonce"],
      pins: pins, now: raw["now"], leeway: raw["leeway"]
    )
  end

  def set_expect(raw, pins)
    StandardId::VoidWhichBinds::SecurityEvent::Expect.new(
      issuer: raw["issuer"], audience: raw["audience"], pins: pins, now: raw["now"], max_age: raw["max_age"]
    )
  end

  # Signs exactly `header` and `payload` (strings) with the key, as
  # josetest.RawSign does: the vector's token must come back byte for byte.
  def raw_sign(key, header, payload)
    jose = StandardId::VoidWhichBinds::Jose
    input = "#{jose.encode(header)}.#{jose.encode(payload)}"
    "#{input}.#{jose.encode(key.sign(nil, input))}"
  end

  def decoded_parts(token)
    header, payload, = token.split(".", -1)
    [StandardId::VoidWhichBinds::Jose.decode(header), StandardId::VoidWhichBinds::Jose.decode(payload)]
  end
end
