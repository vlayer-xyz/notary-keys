import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { checkLive, validate } from "./rules.js";

const production = readFileSync(new URL("../notary-keys.production.json", import.meta.url), "utf8");
const doc = JSON.parse(production);
const [key] = doc.keys;

const NOW = Date.parse("2026-10-01T00:00:00Z");
const PAST = "2026-01-01T00:00:00Z";
const FUTURE = "2027-01-01T00:00:00Z";
const BUMPED = { updatedAt: "2026-09-30T00:00:00Z" };

// The production key's point in uncompressed (04‖x‖y) SubjectPublicKeyInfo form.
const UNCOMPRESSED_PEM =
  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1Mu6mQsMLrHdRbKcfSYHUpnx6jkxfzUU\nDm73HnA77acXaF7sNQHVOPqtLYC1ldmYzWLpT/Pvtnja/1YTblMSMA==\n-----END PUBLIC KEY-----\n";
// An unrelated secp256k1 key, compressed form.
const OTHER = {
  fingerprint: "6cff271c5511747721a2fbe2f1e7f5a9520241bf95d1afc72b34a70e144da0d7",
  publicKeyPem: "-----BEGIN PUBLIC KEY-----\nMDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACZt/aZXbuq7OIL+cOSRqyG9jJTGtxPsPf\nFatke4wKM50=\n-----END PUBLIC KEY-----\n",
  curve: "secp256k1",
  validFrom: PAST,
  validUntil: null,
  meta: { notaryUrls: ["https://notary.example.com"] },
};

const list = (patch = {}, keys = [key]) => `${JSON.stringify({ ...doc, ...patch, keys }, null, 2)}\n`;
const withKey = (patch, listPatch = {}) => list(listPatch, [{ ...key, ...patch }]);
const errors = (raw, options) => validate(raw, { now: NOW, ...options });
const assertRejects = (raw, pattern, options) => {
  const found = errors(raw, options);
  assert.equal(found.length, 1, found.join("\n"));
  assert.match(found[0], pattern);
};

describe("content rules", () => {
  it("accepts the committed production list", () => assert.deepEqual(errors(production), []));
  it("rejects a misspelled field", () => assertRejects(withKey({ validUntill: null }), /schema: .*additional properties/));
  it("rejects a missing field", () => {
    const { meta, ...rest } = key;
    assertRejects(list({}, [rest]), /schema: .*meta/);
  });
  it("rejects a non-https notary URL", () => assertRejects(withKey({ meta: { notaryUrls: ["http://notary.example.com"] } }), /schema: .*notaryUrls/));
  it("rejects an impossible calendar date", () => assertRejects(withKey({ validFrom: "2024-02-30T00:00:00Z" }), /validFrom: .* not a valid UTC instant/));
  it("rejects compact formatting", () => assertRejects(JSON.stringify(doc), /not canonically formatted/));
  it("rejects a missing trailing newline", () => assertRejects(list().trimEnd(), /not canonically formatted/));
  it("rejects updatedAt far in the future", () => assertRejects(list({ updatedAt: FUTURE }), /updatedAt .* in the future/));
  it("rejects a wrong fingerprint", () => assertRejects(withKey({ fingerprint: OTHER.fingerprint }), /fingerprint is .* but sha256/));
  it("rejects a wrong curve", () => assertRejects(withKey({ curve: "secp256r1" }), /curve is secp256r1 but publicKeyPem is secp256k1/));
  it("rejects an uncompressed PEM", () => assertRejects(withKey({ publicKeyPem: UNCOMPRESSED_PEM }), /compressed form/));
  it("rejects a PEM that is not a key", () => {
    const garbage = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
    assertRejects(withKey({ publicKeyPem: garbage }), /does not parse/);
  });
  it("rejects validUntil before validFrom", () => assertRejects(withKey({ validUntil: "2024-01-01T00:00:00Z" }), /validUntil .* not after validFrom/));
  it("rejects duplicate fingerprints", () => assertRejects(list({}, [key, key]), /duplicate fingerprint, first seen at keys\[0\]/));
  it("accepts several distinct keys", () => assert.deepEqual(errors(list({}, [key, OTHER])), []));
});

describe("change rules", () => {
  const against = (base) => ({ base });

  it("accepts an unchanged list", () => assert.deepEqual(errors(production, against(production)), []));
  it("accepts a new key with an updatedAt bump", () => assert.deepEqual(errors(list(BUMPED, [key, OTHER]), against(production)), []));
  it("rejects a change to keys without an updatedAt bump", () => assertRejects(list({}, [key, OTHER]), /keys changed but updatedAt/, against(production)));
  it("rejects removing a key", () => assertRejects(list(BUMPED, [OTHER]), /removed; entries are never deleted/, against(production)));
  for (const [field, value] of [
    ["publicKeyPem", OTHER.publicKeyPem],
    ["curve", "secp256r1"],
    ["validFrom", PAST],
  ]) {
    it(`rejects a change to ${field}`, () => {
      const found = errors(withKey({ [field]: value }, BUMPED), against(production));
      assert.ok(found.some((e) => e.includes(`${field} changed; it is immutable`)), found.join("\n"));
    });
  }
  it("rejects reopening a window that has already closed", () => assertRejects(withKey({ validUntil: null }, BUMPED), /has passed and can only be moved earlier/, against(withKey({ validUntil: PAST }))));
  it("rejects extending a window that has already closed", () => assertRejects(withKey({ validUntil: "2026-02-01T00:00:00Z" }, BUMPED), /has passed and can only be moved earlier/, against(withKey({ validUntil: PAST }))));
  it("accepts shortening a window that has already closed", () => assert.deepEqual(errors(withKey({ validUntil: "2025-12-01T00:00:00Z" }, BUMPED), against(withKey({ validUntil: PAST }))), []));
  it("accepts closing an open window", () => assert.deepEqual(errors(withKey({ validUntil: FUTURE }, BUMPED), against(production)), []));
  it("accepts reopening or moving a window that has not closed yet", () => {
    const base = withKey({ validUntil: FUTURE });
    assert.deepEqual(errors(withKey({ validUntil: null }, BUMPED), against(base)), []);
    assert.deepEqual(errors(withKey({ validUntil: "2028-01-01T00:00:00Z" }, BUMPED), against(base)), []);
  });
});

describe("live check", () => {
  const serving = (publicKeyByUrl) => async (url) => {
    const publicKey = publicKeyByUrl[url];
    if (publicKey === undefined) throw new Error("ECONNREFUSED");
    return { ok: true, json: async () => ({ publicKey }) };
  };
  const warnings = (raw, fetch) => checkLive(raw, { now: NOW, fetch });
  const [productionUrl, legacyUrl] = key.meta.notaryUrls;

  it("is silent when every notary serves the listed key", async () => {
    const fetch = serving({ [`${productionUrl}/info`]: key.publicKeyPem, [`${legacyUrl}/info`]: key.publicKeyPem });
    assert.deepEqual(await warnings(production, fetch), []);
  });
  it("warns per notary that serves a different key or is unreachable", async () => {
    const fetch = serving({ [`${productionUrl}/info`]: OTHER.publicKeyPem });
    const found = await warnings(production, fetch);
    assert.equal(found.length, 2);
    assert.match(found[0], /serves a different publicKey/);
    assert.match(found[1], /unreachable: ECONNREFUSED/);
  });
  it("warns on a non-2xx response", async () => {
    const fetch = async () => ({ ok: false, status: 503 });
    assert.match((await warnings(withKey({ meta: { notaryUrls: [productionUrl] } }), fetch))[0], /HTTP 503/);
  });
  it("skips keys whose window is closed or has not opened yet", async () => {
    const fetch = async () => assert.fail("must not fetch");
    assert.deepEqual(await warnings(withKey({ validUntil: PAST }), fetch), []);
    assert.deepEqual(await warnings(withKey({ validFrom: FUTURE }), fetch), []);
  });
});
