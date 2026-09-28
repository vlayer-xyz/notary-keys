import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";

const published = JSON.parse(readFileSync(new URL("../schema.json", import.meta.url), "utf8"));
const ajv = new Ajv2020({ allErrors: true, schemas: [published] });
const matchesPublishedSchema = ajv.getSchema(published.$id);
// The published schema is lenient so that verifiers keep working when fields are added. Our own
// lists are held to a stricter shape: nothing outside the described fields (so a typo like
// `validUntill` fails) except inside `meta`, and `meta.notaryUrls` present for the live check.
const matchesStrictSchema = ajv.compile({
  $ref: published.$id,
  type: "object",
  unevaluatedProperties: false,
  properties: {
    keys: {
      type: "array",
      items: {
        $ref: `${published.$id}#/$defs/key`,
        type: "object",
        unevaluatedProperties: false,
        required: ["meta"],
        properties: { meta: { type: "object", required: ["notaryUrls"] } },
      },
    },
  },
});

// node:crypto reports OpenSSL curve names; the list uses SEC 2 names.
const CURVES = { secp256k1: "secp256k1", prime256v1: "secp256r1" };
// SubjectPublicKeyInfo DER up to (excluding) the 33-byte compressed point, per curve.
const SPKI_PREFIX = {
  secp256k1: Buffer.from("3036301006072a8648ce3d020106052b8104000a032200", "hex"),
  secp256r1: Buffer.from("3039301306072a8648ce3d020106082a8648ce3d030107032200", "hex"),
};
const IMMUTABLE = ["publicKeyPem", "curve", "validFrom"];
const DAY_MS = 24 * 60 * 60 * 1000;
const RETROACTIVE_GRACE_DAYS = 7;
const LIVE_TIMEOUT_MS = 15_000;
const LIVE_MAX_BODY_BYTES = 64 * 1024;

const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const time = (timestamp) => Date.parse(timestamp);
const isInstant = (timestamp) => new Date(timestamp).toJSON() === timestamp.replace("Z", ".000Z");
const label = (key, index) => `keys[${index}] (${key.fingerprint.slice(0, 12)}…)`;
const isOpen = (key, now) =>
  time(key.validFrom) <= now && (key.validUntil === null || now < time(key.validUntil));
const toPem = (der) =>
  `-----BEGIN PUBLIC KEY-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;

/** Curve, compressed SEC1 point and the canonical compressed-point SPKI PEM of a public key. */
function parseKey(pem) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ec") throw new Error(`not an EC key (${key.asymmetricKeyType})`);
  const curve = CURVES[key.asymmetricKeyDetails.namedCurve];
  if (curve === undefined) throw new Error(`unsupported curve ${key.asymmetricKeyDetails.namedCurve}`);
  const { x, y } = key.export({ format: "jwk" });
  const yBytes = Buffer.from(y, "base64url");
  const point = Buffer.concat([Buffer.from([2 + (yBytes.at(-1) & 1)]), Buffer.from(x, "base64url")]);
  return { curve, point, canonicalPem: toPem(Buffer.concat([SPKI_PREFIX[curve], point])) };
}

function describeSchemaError({ instancePath, message, params }) {
  const path = instancePath || "<root>";
  const unknown = params.additionalProperty ?? params.unevaluatedProperty;
  if (unknown !== undefined) return `schema: ${path} has unknown field "${unknown}"`;
  if (params.allowedValue !== undefined) return `schema: ${path} ${message}: ${JSON.stringify(params.allowedValue)}`;
  if (params.allowedValues !== undefined) {
    return `schema: ${path} ${message}: ${params.allowedValues.map((value) => JSON.stringify(value)).join(", ")}`;
  }
  return `schema: ${path} ${message}`;
}

/** The schema only checks the shape of timestamps; this checks they denote real instants. */
function checkTimestamps(doc) {
  const fields = [
    ["updatedAt", doc.updatedAt],
    ...doc.keys.flatMap((key, i) => [
      [`keys[${i}].validFrom`, key.validFrom],
      [`keys[${i}].validUntil`, key.validUntil],
    ]),
  ];
  return fields
    .filter(([, value]) => value !== null && !isInstant(value))
    .map(([path, value]) => `${path}: ${value} is not a valid UTC instant`);
}

// Each rule below takes { raw, doc, base, now } and returns a list of error messages. They may
// assume `doc` matches the strict schema and every timestamp is a real instant.

function checkFormatting({ raw, doc }) {
  return raw === canonical(doc) ? [] : ["file is not canonically formatted (2-space indent, trailing newline)"];
}

function checkUpdatedAt({ doc, now }) {
  return time(doc.updatedAt) > now + DAY_MS ? [`updatedAt ${doc.updatedAt} is more than 24h in the future`] : [];
}

function checkUniqueFingerprints({ doc }) {
  const seen = new Map();
  return doc.keys.flatMap((key, i) => {
    const first = seen.get(key.fingerprint);
    seen.set(key.fingerprint, first ?? i);
    return first === undefined ? [] : [`keys[${i}]: duplicate fingerprint, first seen at keys[${first}]`];
  });
}

function checkKeys({ doc }) {
  return doc.keys.flatMap((key, i) => {
    const errors = [];
    let parsed;
    try {
      parsed = parseKey(key.publicKeyPem);
    } catch (cause) {
      return [`${label(key, i)}: publicKeyPem does not parse: ${cause.message}`];
    }
    const fingerprint = createHash("sha256").update(parsed.point).digest("hex");
    if (parsed.curve !== key.curve) {
      errors.push(`${label(key, i)}: curve is ${key.curve} but publicKeyPem is ${parsed.curve}`);
    }
    if (fingerprint !== key.fingerprint) {
      errors.push(`${label(key, i)}: fingerprint is ${key.fingerprint} but sha256(compressed point) is ${fingerprint}`);
    }
    if (key.publicKeyPem !== parsed.canonicalPem) {
      const expected = JSON.stringify(parsed.canonicalPem);
      errors.push(`${label(key, i)}: publicKeyPem must be the compressed-point SPKI PEM as the notary's GET /info returns it: ${expected}`);
    }
    if (key.validUntil !== null && time(key.validUntil) <= time(key.validFrom)) {
      errors.push(`${label(key, i)}: validUntil ${key.validUntil} is not after validFrom ${key.validFrom}`);
    }
    return errors;
  });
}

/**
 * Change rules against the previous version: entries are append-only, identity fields are
 * immutable, an already-closed window may only be shortened, nothing is dated more than
 * RETROACTIVE_GRACE_DAYS into the past, and `updatedAt` never moves backwards and is bumped
 * whenever `keys` changed.
 */
function checkChanges({ doc, base, now }) {
  if (base === undefined) return [];
  const errors = [];
  const earliest = now - RETROACTIVE_GRACE_DAYS * DAY_MS;
  const retroactive = `more than ${RETROACTIVE_GRACE_DAYS} days in the past`;
  const previous = new Map(base.keys.map((key) => [key.fingerprint, key]));

  doc.keys.forEach((key, i) => {
    const old = previous.get(key.fingerprint);
    if (old === undefined) {
      if (time(key.validFrom) < earliest) {
        errors.push(`${label(key, i)}: new entry with validFrom ${key.validFrom} ${retroactive}; entries cannot be backdated`);
      }
      return;
    }
    for (const field of IMMUTABLE) {
      if (key[field] !== old[field]) errors.push(`${label(key, i)}: ${field} changed; it is immutable once published`);
    }
    const wasClosed = old.validUntil !== null && time(old.validUntil) <= now;
    if (wasClosed) {
      if (key.validUntil === null || time(key.validUntil) > time(old.validUntil)) {
        errors.push(`${label(key, i)}: validUntil ${old.validUntil} has passed and can only be moved earlier`);
      }
    } else if (key.validUntil !== null && time(key.validUntil) < earliest) {
      errors.push(
        `${label(key, i)}: validUntil ${key.validUntil} is ${retroactive}; this retroactively invalidates proofs and cannot be undone`,
      );
    }
  });

  for (const old of base.keys) {
    if (!doc.keys.some((key) => key.fingerprint === old.fingerprint)) {
      errors.push(`key ${old.fingerprint.slice(0, 12)}…: removed; entries are never deleted, set validUntil instead`);
    }
  }

  if (time(doc.updatedAt) < time(base.updatedAt)) {
    errors.push(`updatedAt ${doc.updatedAt} is before the previous version's ${base.updatedAt}`);
  } else if (canonical(doc.keys) !== canonical(base.keys) && time(doc.updatedAt) === time(base.updatedAt)) {
    errors.push(`keys changed but updatedAt ${doc.updatedAt} was not bumped; set it to the current UTC time`);
  }
  return errors;
}

function parseJson(raw, what) {
  try {
    return { doc: JSON.parse(raw) };
  } catch (cause) {
    return { error: `${what} is not valid JSON: ${cause.message}` };
  }
}

/**
 * Validates the raw contents of a key list. `base` is the raw previous version (enables the
 * change rules); `now` is the reference time for the window rules.
 * @returns {string[]} error messages, empty when the list is valid
 */
export function validate(raw, { base, now = Date.now() } = {}) {
  const { doc, error } = parseJson(raw, "file");
  if (error !== undefined) return [error];
  if (!matchesStrictSchema(doc)) return [...new Set(matchesStrictSchema.errors.map(describeSchemaError))];
  const timestampErrors = checkTimestamps(doc);
  if (timestampErrors.length > 0) return timestampErrors;

  let baseDoc;
  if (base !== undefined) {
    const parsed = parseJson(base, "previous version");
    if (parsed.error !== undefined) return [parsed.error];
    if (!matchesPublishedSchema(parsed.doc)) return ["previous version does not match the schema; change rules cannot run"];
    baseDoc = parsed.doc;
  }

  const context = { raw, doc, base: baseDoc, now };
  return [checkFormatting, checkUpdatedAt, checkUniqueFingerprints, checkKeys, checkChanges].flatMap((rule) => rule(context));
}

async function readBody(response, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) throw new Error(`body exceeds ${limit} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function probeNotary(url, key, name, fetch) {
  let response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(LIVE_TIMEOUT_MS) });
  } catch (cause) {
    return `${name}: ${url} unreachable: ${cause.message}`;
  }
  if (!response.ok) return `${name}: ${url} returned HTTP ${response.status}`;
  let body;
  try {
    body = await readBody(response, LIVE_MAX_BODY_BYTES);
  } catch (cause) {
    return `${name}: ${url} body could not be read: ${cause.message}`;
  }
  const { doc: info, error } = parseJson(body, "response");
  if (error !== undefined) return `${name}: ${url} did not return JSON`;
  if (typeof info?.publicKey !== "string") return `${name}: ${url} response has no publicKey field`;
  return info.publicKey === key.publicKeyPem ? null : `${name}: ${url} serves a different publicKey than publicKeyPem`;
}

/**
 * Fetches GET /info from every notary of every open-window key and compares the served key
 * with the listed one. Advisory: a mismatch is expected while a rotation is in progress.
 * Expects `raw` to have passed `validate`.
 * @returns {Promise<string[]>} warning messages
 */
export async function checkLive(raw, { now = Date.now(), fetch = globalThis.fetch } = {}) {
  const { keys } = JSON.parse(raw);
  const probes = keys.flatMap((key, i) =>
    isOpen(key, now) ? key.meta.notaryUrls.map((url) => probeNotary(`${url}/info`, key, label(key, i), fetch)) : [],
  );
  return (await Promise.all(probes)).filter((warning) => warning !== null);
}
