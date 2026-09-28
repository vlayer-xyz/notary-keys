import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { CURVES, checkLive, validate } from "./rules.js";

// Fixtures are frozen here rather than read from the committed list, so that editing the list
// never breaks the validator's own tests. The reference time is fixed; `RECENT` is inside the
// 7-day retroactive grace, `PAST` is well outside it and `FUTURE` is a year ahead.
const NOW = Date.parse("2026-10-01T00:00:00Z");
const RECENT = "2026-09-28T00:00:00Z";
const PAST = "2026-01-01T00:00:00Z";
const FUTURE = "2027-01-01T00:00:00Z";
const BUMPED = { updatedAt: "2026-09-30T00:00:00Z" };
const time = Date.parse;
const at = (ms) => new Date(ms).toISOString().replace(".000Z", "Z");
const SECOND = 1000;
const HOUR = 60 * 60 * SECOND;
const DAY = 24 * HOUR;
const GRACE_EDGE = at(NOW - 7 * DAY);

const KEY = {
  fingerprint: "a7e62d7f17aa7a22c26bdb93b7ce9400e826ffb2c6f54e54d2ded015677499af",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDYwEAYHKoZIzj0CAQYFK4EEAAoDIgAC1Mu6mQsMLrHdRbKcfSYHUpnx6jkxfzUU\nDm73HnA77ac=\n-----END PUBLIC KEY-----\n",
  curve: "secp256k1",
  validFrom: "2024-11-28T00:00:00Z",
  validUntil: null,
  meta: { notaryUrls: ["https://notary.example.com", "https://legacy.example.com"] },
};
// KEY's point in uncompressed (04‖x‖y) SubjectPublicKeyInfo form.
const UNCOMPRESSED_PEM =
  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1Mu6mQsMLrHdRbKcfSYHUpnx6jkxfzUU\nDm73HnA77acXaF7sNQHVOPqtLYC1ldmYzWLpT/Pvtnja/1YTblMSMA==\n-----END PUBLIC KEY-----\n";
const OTHER = {
  fingerprint: "6cff271c5511747721a2fbe2f1e7f5a9520241bf95d1afc72b34a70e144da0d7",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACZt/aZXbuq7OIL+cOSRqyG9jJTGtxPsPf\nFatke4wKM50=\n-----END PUBLIC KEY-----\n",
  curve: "secp256k1",
  validFrom: RECENT,
  validUntil: null,
  meta: { notaryUrls: ["https://other.example.com"] },
};

const P256 = {
  fingerprint: "4881d57e2983140922e2e6ff82a8debde60efe9dfe602b7cb790864fed74d45b",
  publicKeyPem:
    "-----BEGIN PUBLIC KEY-----\nMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADu2+daX2o5/bkgvgRBPyUupnPSeQx\nH7QkhXnJ7SE6fzw=\n-----END PUBLIC KEY-----\n",
  curve: "secp256r1",
  validFrom: RECENT,
  validUntil: null,
  meta: { notaryUrls: ["https://p256.example.com"] },
};

const ED25519_PEM =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJg74j33enoHb3BSx6aNgl7nTQzDus+JoHDxI9/gzjHs=\n-----END PUBLIC KEY-----\n";
const P384_PEM =
  "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERAVYS0YoyeTEGAW04+Pawg8ogeI0+JqI\n98crnO8GUDpldZwRdVRuwJI+L2SwOuRxKhiBWe9DHhNU6+GPgNoc4Icaq6DTzbfh\ng7D437He82CWAchvPoidvGEvDXY1Xn4E\n-----END PUBLIC KEY-----\n";
// secp256k1 SubjectPublicKeyInfo whose point is the single byte 00: the point at infinity.
const INFINITY_PEM = "-----BEGIN PUBLIC KEY-----\nMBYwEAYHKoZIzj0CAQYFK4EEAAoDAgAA\n-----END PUBLIC KEY-----\n";

const FIXTURE = {
  schemaVersion: 1,
  updatedAt: "2026-09-01T00:00:00Z",
  fingerprintAlgorithm: "sha256 over compressed SEC1 public key, lowercase hex",
  keys: [KEY],
};

const list = (patch = {}, keys = [KEY]) => `${JSON.stringify({ ...FIXTURE, ...patch, keys }, null, 2)}\n`;
const withKey = (patch, listPatch = {}) => list(listPatch, [{ ...KEY, ...patch }]);
const errors = (raw, options) => validate(raw, { now: NOW, ...options });
const assertAccepts = (raw, options) => assert.deepEqual(errors(raw, options), []);
const assertRejects = (raw, pattern, options) => {
  const found = errors(raw, options);
  assert.equal(found.length, 1, found.join("\n"));
  assert.match(found[0], pattern);
};

describe("content rules", () => {
  it("accepts the committed production list", () => {
    const production = readFileSync(new URL("../notary-keys.production.json", import.meta.url), "utf8");
    assert.deepEqual(validate(production, { base: production }), []);
  });

  it("accepts the fixture", () => assertAccepts(list()));

  it("rejects a file that is not JSON", () => assertRejects("{", /file is not valid JSON/));

  it("rejects a misspelled field", () =>
    assertRejects(withKey({ validUntill: null }), /schema: \/keys\/0 has unknown field "validUntill"/));

  it("rejects an unknown top-level field", () =>
    assertRejects(list({ comment: "x" }), /schema: <root> has unknown field "comment"/));

  it("accepts unknown fields inside meta", () => assertAccepts(withKey({ meta: { ...KEY.meta, owner: "x" } })));

  it("rejects a missing field", () => {
    const { meta, ...rest } = KEY;
    assertRejects(list({}, [rest]), /schema: \/keys\/0 must have required property 'meta'/);
  });

  it("rejects meta without notaryUrls", () => {
    assertRejects(withKey({ meta: {} }), /schema: \/keys\/0\/meta must have required property 'notaryUrls'/);
  });

  it("names the allowed values for an unknown curve", () => {
    assertRejects(
      withKey({ curve: "P-256" }),
      /schema: \/keys\/0\/curve must be equal to one of the allowed values: "secp256k1", "secp256r1"/,
    );
  });

  for (const url of [
    "http://notary.example.com",
    "https://notary.example.com/",
    "https://notary.example.com?x=1",
    "https://user:pw@notary.example.com",
  ]) {
    it(`rejects notary URL ${url}`, () =>
      assertRejects(withKey({ meta: { notaryUrls: [url] } }), /schema: .*notaryUrls/));
  }

  it("accepts a notary URL with a port", () =>
    assertAccepts(withKey({ meta: { notaryUrls: ["https://notary.example.com:7047"] } })));

  it("rejects an impossible calendar date", () => {
    assertRejects(withKey({ validFrom: "2024-02-30T00:00:00Z" }), /validFrom: .* not a valid UTC instant/);
  });

  it("rejects compact formatting", () => assertRejects(JSON.stringify(FIXTURE), /not canonically formatted/));

  it("rejects a missing trailing newline", () => assertRejects(list().trimEnd(), /not canonically formatted/));

  it("accepts updatedAt up to 1h in the future and rejects beyond", () => {
    assertAccepts(list({ updatedAt: at(NOW + HOUR) }));
    assertRejects(list({ updatedAt: at(NOW + HOUR + SECOND) }), /updatedAt .* is more than 1h in the future/);
  });

  it("rejects a wrong fingerprint", () =>
    assertRejects(withKey({ fingerprint: OTHER.fingerprint }), /fingerprint is .* but sha256/));

  it("rejects a wrong curve", () =>
    assertRejects(withKey({ curve: "secp256r1" }), /curve is secp256r1 but publicKeyPem is secp256k1/));

  it("rejects a secp256r1 key labelled secp256k1 or with a secp256k1 fingerprint", () => {
    assertRejects(list({}, [{ ...P256, curve: "secp256k1" }]), /curve is secp256k1 but publicKeyPem is secp256r1/);
    assertRejects(list({}, [{ ...P256, fingerprint: KEY.fingerprint }]), /fingerprint is .* but sha256/);
  });

  it("rejects an uncompressed PEM and shows the expected one", () => {
    const [found] = errors(withKey({ publicKeyPem: UNCOMPRESSED_PEM }));
    assert.match(found, /compressed-point/);
    assert.ok(found.endsWith(JSON.stringify(KEY.publicKeyPem)), found);
  });

  it("rejects a PEM with non-canonical line wrapping", () => {
    assertRejects(withKey({ publicKeyPem: KEY.publicKeyPem.replace("UU\nDm", "UUDm") }), /compressed-point/);
  });

  it("rejects a PEM that is not a key", () => {
    const garbage = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
    assertRejects(withKey({ publicKeyPem: garbage }), /does not parse/);
  });

  it("rejects a non-EC key", () =>
    assertRejects(withKey({ publicKeyPem: ED25519_PEM }), /does not parse: not an EC key \(ed25519\)/));

  it("rejects an unsupported curve", () =>
    assertRejects(withKey({ publicKeyPem: P384_PEM }), /does not parse: unsupported curve secp384r1/));

  it("rejects the point at infinity", () =>
    assertRejects(withKey({ publicKeyPem: INFINITY_PEM }), /does not parse: .*invalid form/));

  it("accepts a secp256r1 key", () => assertAccepts(list({}, [P256])));

  it("supports exactly the curves the schema allows", () => {
    const schema = JSON.parse(readFileSync(new URL("../schema.json", import.meta.url), "utf8"));
    assert.deepEqual(
      schema.$defs.key.properties.curve.enum.sort(),
      Object.values(CURVES)
        .map((curve) => curve.name)
        .sort(),
    );
  });

  it("rejects validUntil not after validFrom", () => {
    assertRejects(withKey({ validUntil: "2024-01-01T00:00:00Z" }), /validUntil .* not after validFrom/);
    assertRejects(withKey({ validUntil: KEY.validFrom }), /validUntil .* not after validFrom/);
    assertAccepts(withKey({ validUntil: at(time(KEY.validFrom) + SECOND) }));
  });

  it("rejects duplicate fingerprints", () =>
    assertRejects(list({}, [KEY, KEY]), /duplicate fingerprint, first seen at keys\[0\]/));

  it("accepts several distinct keys", () => assertAccepts(list({}, [KEY, OTHER, P256])));
});

describe("change rules", () => {
  const against = (base = list()) => ({ base });

  it("accepts an unchanged list", () => assertAccepts(list(), against()));

  it("rejects a previous version that is not JSON", () =>
    assertRejects(list(), /previous version is not valid JSON/, against("{")));

  it("rejects a previous version that is not a valid list", () => {
    const invalid = /previous version is not a valid list; change rules cannot run/;
    assertRejects(list(), invalid, against("{}\n"));
    assertRejects(list(), invalid, against(withKey({ validUntil: "2026-02-30T00:00:00Z" })));
    assertRejects(list(), invalid, against(list({}, [KEY, { ...KEY, validFrom: PAST }])));
  });

  it("accepts a new key with an updatedAt bump", () => assertAccepts(list(BUMPED, [KEY, OTHER]), against()));

  it("accepts a new key whose window opens in the future", () => {
    assertAccepts(list(BUMPED, [KEY, { ...OTHER, validFrom: FUTURE }]), against());
  });

  it("rejects a new key backdated beyond the grace period", () => {
    const backdated = (validFrom) => list(BUMPED, [KEY, { ...OTHER, validFrom }]);
    assertAccepts(backdated(GRACE_EDGE), against());
    assertRejects(
      backdated(at(time(GRACE_EDGE) - SECOND)),
      /keys\[1\] .*: new entry with validFrom .* more than 7 days in the past/,
      against(),
    );
    assertRejects(backdated(PAST), /keys\[1\] .*: new entry with validFrom .* more than 7 days in the past/, against());
  });

  it("rejects a change to keys without an updatedAt bump", () => {
    assertRejects(list({}, [KEY, OTHER]), /list changed but updatedAt .* was not bumped/, against());
  });

  it("rejects a meta-only change without an updatedAt bump", () => {
    assertRejects(
      withKey({ meta: { notaryUrls: ["https://new.example.com"] } }),
      /list changed but updatedAt/,
      against(),
    );
  });

  it("accepts an updatedAt bump by itself", () => assertAccepts(list(BUMPED), against()));

  it("rejects a change with an updatedAt bump that is not recent", () => {
    const stale = /list changed but updatedAt .* is more than 7 days in the past; set it to the current UTC time/;
    assertRejects(list({ updatedAt: "2026-09-02T00:00:00Z" }, [KEY, OTHER]), stale, against());
    assertRejects(list({ updatedAt: at(time(GRACE_EDGE) - SECOND) }, [KEY, OTHER]), stale, against());
    assertAccepts(list({ updatedAt: GRACE_EDGE }, [KEY, OTHER]), against());
    assertAccepts(list({ updatedAt: "2026-09-02T00:00:00Z" }), against());
  });

  it("rejects updatedAt moving backwards", () => {
    assertRejects(list({ updatedAt: PAST }), /updatedAt .* is before the previous version's/, against());
  });

  it("rejects removing a key", () =>
    assertRejects(list(BUMPED, [{ ...OTHER, validFrom: RECENT }]), /removed; entries are never deleted/, against()));

  for (const [field, value] of [
    ["publicKeyPem", OTHER.publicKeyPem],
    ["curve", "secp256r1"],
  ]) {
    it(`rejects a change to ${field}`, () => {
      const found = errors(withKey({ [field]: value }, BUMPED), against());
      assert.ok(
        found.some((e) => e.includes(`${field} changed; it is immutable`)),
        found.join("\n"),
      );
    });
  }

  it("rejects a change to validFrom once the window has opened", () => {
    assertRejects(withKey({ validFrom: PAST }, BUMPED), /validFrom .* has passed and is immutable/, against());
    assertRejects(withKey({ validFrom: FUTURE }, BUMPED), /validFrom .* has passed and is immutable/, against());
    assertRejects(
      withKey({ validFrom: PAST }, BUMPED),
      /validFrom .* has passed and is immutable/,
      against(withKey({ validFrom: at(NOW) })),
    );
  });

  it("accepts correcting validFrom while the window has not opened, within the grace period", () => {
    const scheduled = against(withKey({ validFrom: FUTURE, validUntil: null }));
    assertAccepts(withKey({ validFrom: "2027-02-01T00:00:00Z" }, BUMPED), scheduled);
    assertAccepts(withKey({ validFrom: RECENT }, BUMPED), scheduled);
    assertAccepts(withKey({ validFrom: GRACE_EDGE }, BUMPED), scheduled);
    assertRejects(
      withKey({ validFrom: PAST }, BUMPED),
      /validFrom .* more than 7 days in the past; entries cannot be backdated/,
      scheduled,
    );
    assertAccepts(withKey({ validFrom: RECENT }, BUMPED), against(withKey({ validFrom: at(NOW + SECOND) })));
  });

  const retroactive = /validUntil .* is more than 7 days in the past; this retroactively invalidates proofs/;

  describe("window already closed at the previous version", () => {
    const CLOSED_AT = "2026-09-29T00:00:00Z";
    const closed = against(withKey({ validUntil: CLOSED_AT }));

    it("rejects reopening it", () =>
      assertRejects(withKey({ validUntil: null }, BUMPED), /has passed and can only be moved earlier/, closed));

    it("rejects extending it, even by a second", () => {
      assertRejects(withKey({ validUntil: FUTURE }, BUMPED), /has passed and can only be moved earlier/, closed);
      assertRejects(
        withKey({ validUntil: at(time(CLOSED_AT) + SECOND) }, BUMPED),
        /has passed and can only be moved earlier/,
        closed,
      );
    });

    it("treats a window closing exactly now as closed", () => {
      assertRejects(
        withKey({ validUntil: null }, BUMPED),
        /has passed and can only be moved earlier/,
        against(withKey({ validUntil: at(NOW) })),
      );
    });

    it("accepts shortening it within the grace period", () =>
      assertAccepts(withKey({ validUntil: RECENT }, BUMPED), closed));

    it("rejects shortening it beyond the grace period", () => {
      assertRejects(withKey({ validUntil: PAST }, BUMPED), retroactive, closed);
      assertRejects(
        withKey({ validUntil: "2025-12-01T00:00:00Z" }, BUMPED),
        retroactive,
        against(withKey({ validUntil: PAST })),
      );
    });

    it("accepts leaving a long-closed window alone", () =>
      assertAccepts(withKey({ validUntil: PAST }, BUMPED), against(withKey({ validUntil: PAST }))));
  });

  it("accepts closing an open window in the future or within the grace period", () => {
    assertAccepts(withKey({ validUntil: FUTURE }, BUMPED), against());
    assertAccepts(withKey({ validUntil: RECENT }, BUMPED), against());
    assertAccepts(withKey({ validUntil: GRACE_EDGE }, BUMPED), against());
  });

  it("rejects closing an open window beyond the grace period", () => {
    assertRejects(withKey({ validUntil: at(time(GRACE_EDGE) - SECOND) }, BUMPED), retroactive, against());
    assertRejects(withKey({ validUntil: PAST }, BUMPED), retroactive, against());
    assertRejects(withKey({ validUntil: PAST }, BUMPED), retroactive, against(withKey({ validUntil: FUTURE })));
  });

  it("accepts reopening or moving a window that has not closed yet", () => {
    const base = against(withKey({ validUntil: FUTURE }));
    assertAccepts(withKey({ validUntil: null }, BUMPED), base);
    assertAccepts(withKey({ validUntil: "2028-01-01T00:00:00Z" }, BUMPED), base);
    assertAccepts(withKey({ validUntil: null }, BUMPED), against(withKey({ validUntil: at(NOW + SECOND) })));
  });
});

describe("live check", () => {
  const json = (body, init) => new Response(JSON.stringify(body), { status: 200, ...init });
  const serving = (publicKeyByUrl) => async (url) => {
    const publicKey = publicKeyByUrl[url];
    if (publicKey === undefined) throw new Error("ECONNREFUSED");
    return json({ publicKey });
  };

  const warnings = (raw, fetch) => checkLive(raw, { now: NOW, fetch });
  const [primaryUrl, legacyUrl] = KEY.meta.notaryUrls;
  const single = (fetch) => warnings(withKey({ meta: { notaryUrls: [primaryUrl] } }), fetch);

  it("is silent when every notary serves the listed key", async () => {
    const fetch = serving({ [`${primaryUrl}/info`]: KEY.publicKeyPem, [`${legacyUrl}/info`]: KEY.publicKeyPem });
    assert.deepEqual(await warnings(list(), fetch), []);
  });

  it("warns per notary that serves a different key or is unreachable", async () => {
    const fetch = serving({ [`${primaryUrl}/info`]: OTHER.publicKeyPem });
    const found = await warnings(list(), fetch);
    assert.equal(found.length, 2);
    assert.match(found[0], /serves a different publicKey/);
    assert.match(found[1], /unreachable: ECONNREFUSED/);
  });

  it("warns when the served PEM differs only in whitespace", async () => {
    assert.match(
      (await single(async () => json({ publicKey: KEY.publicKeyPem.trimEnd() })))[0],
      /serves a different publicKey/,
    );
  });

  it("warns on a non-2xx response", async () => {
    assert.match((await single(async () => new Response("", { status: 503 })))[0], /HTTP 503/);
  });

  it("warns on a redirect instead of following it, naming the underlying cause", async () => {
    const fetch = async (url, init) => {
      assert.equal(init.redirect, "error");
      throw new TypeError("fetch failed", { cause: new Error("unexpected redirect") });
    };
    assert.match((await single(fetch))[0], /unreachable: unexpected redirect/);
  });

  it("gives up on a body that stalls past the timeout", async () => {
    const stalled = () =>
      new Response(new ReadableStream({ start: (controller) => controller.enqueue(new Uint8Array([123])) }), {
        status: 200,
      });

    const found = await checkLive(withKey({ meta: { notaryUrls: [primaryUrl] } }), {
      now: NOW,
      fetch: async () => stalled(),
      timeoutMs: 50,
    });
    assert.match(found[0], /body could not be read: .*timeout/i);
  });

  it("warns on an empty body", async () => {
    assert.match((await single(async () => new Response(null, { status: 200 })))[0], /returned an empty body/);
    assert.match((await single(async () => new Response("", { status: 200 })))[0], /returned an empty body/);
  });

  it("warns on a body that is not JSON", async () => {
    assert.match((await single(async () => new Response("<html>", { status: 200 })))[0], /did not return JSON/);
  });

  it("warns on a JSON body without publicKey", async () => {
    assert.match((await single(async () => json({ version: "1" })))[0], /has no publicKey field/);
  });

  it("warns on an oversized body", async () => {
    assert.match(
      (await single(async () => new Response("x".repeat(65_537), { status: 200 })))[0],
      /body could not be read: body exceeds/,
    );
  });

  it("skips keys whose window is closed or has not opened yet", async () => {
    const fetch = async () => assert.fail("must not fetch");
    assert.deepEqual(await warnings(withKey({ validUntil: PAST }), fetch), []);
    assert.deepEqual(await warnings(withKey({ validUntil: at(NOW) }), fetch), []);
    assert.deepEqual(await warnings(withKey({ validFrom: FUTURE }), fetch), []);
    assert.deepEqual(await warnings(withKey({ validFrom: at(NOW + SECOND) }), fetch), []);
  });

  it("probes keys whose window opens exactly now or closes a second later", async () => {
    let probes = 0;
    const fetch = async () => (probes++, json({ publicKey: KEY.publicKeyPem }));
    assert.deepEqual(await single(fetch), []);
    assert.deepEqual(
      await warnings(
        withKey({ validFrom: at(NOW), validUntil: at(NOW + SECOND), meta: { notaryUrls: [primaryUrl] } }),
        fetch,
      ),
      [],
    );
    assert.equal(probes, 2);
  });
});
