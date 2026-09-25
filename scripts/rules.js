import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";

const schema = JSON.parse(readFileSync(new URL("../schema.json", import.meta.url), "utf8"));
const matchesSchema = new Ajv2020({ allErrors: true }).compile(schema);

// node:crypto reports OpenSSL curve names; the list uses SEC 2 names.
const CURVES = { secp256k1: "secp256k1", prime256v1: "secp256r1" };
const IMMUTABLE = ["publicKeyPem", "curve", "validFrom"];
const COMPRESSED_POINT_BYTES = 33;
const DAY_MS = 24 * 60 * 60 * 1000;
const LIVE_TIMEOUT_MS = 15_000;

const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const time = (timestamp) => Date.parse(timestamp);
const isInstant = (timestamp) => new Date(timestamp).toJSON() === timestamp.replace("Z", ".000Z");
const label = (key, index) => `keys[${index}] (${key.fingerprint.slice(0, 12)}…)`;
const isOpen = (key, now) => time(key.validFrom) <= now && (key.validUntil === null || now < time(key.validUntil));

/** Curve, compressed SEC1 point and raw SubjectPublicKeyInfo DER of a PEM public key. */
function parseKey(pem) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ec") throw new Error(`not an EC key (${key.asymmetricKeyType})`);
  const curve = CURVES[key.asymmetricKeyDetails.namedCurve];
  if (curve === undefined) throw new Error(`unsupported curve ${key.asymmetricKeyDetails.namedCurve}`);
  const { x, y } = key.export({ format: "jwk" });
  const yBytes = Buffer.from(y, "base64url");
  const point = Buffer.concat([Buffer.from([2 + (yBytes.at(-1) & 1)]), Buffer.from(x, "base64url")]);
  const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ""), "base64");
  return { curve, point, der };
}

// Each rule takes { raw, doc, base, now } and returns a list of error messages.

/** The schema only checks the shape of timestamps; this checks they denote real instants. */
function checkTimestamps({ doc }) {
  const fields = [["updatedAt", doc.updatedAt]];
  doc.keys.forEach((key, i) => fields.push([`keys[${i}].validFrom`, key.validFrom], [`keys[${i}].validUntil`, key.validUntil]));
  return fields.filter(([, value]) => value !== null && !isInstant(value)).map(([path, value]) => `${path}: ${value} is not a valid UTC instant`);
}

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
    if (parsed.curve !== key.curve) errors.push(`${label(key, i)}: curve is ${key.curve} but publicKeyPem is ${parsed.curve}`);
    if (fingerprint !== key.fingerprint) errors.push(`${label(key, i)}: fingerprint is ${key.fingerprint} but sha256(compressed point) is ${fingerprint}`);
    if (!parsed.der.subarray(-COMPRESSED_POINT_BYTES).equals(parsed.point)) {
      errors.push(`${label(key, i)}: publicKeyPem must encode the point in compressed form, as the notary's GET /info returns it`);
    }
    if (key.validUntil !== null && time(key.validUntil) <= time(key.validFrom)) {
      errors.push(`${label(key, i)}: validUntil ${key.validUntil} is not after validFrom ${key.validFrom}`);
    }
    return errors;
  });
}

/**
 * Change rules against the previous version: entries are append-only, identity fields are
 * immutable, an already-closed window may only be shortened, and any change to `keys` bumps `updatedAt`.
 */
function checkChanges({ doc, base, now }) {
  if (base === undefined) return [];
  const errors = [];
  const current = new Map(doc.keys.map((key) => [key.fingerprint, key]));
  for (const old of base.keys) {
    const name = `key ${old.fingerprint.slice(0, 12)}…`;
    const key = current.get(old.fingerprint);
    if (key === undefined) {
      errors.push(`${name}: removed; entries are never deleted, set validUntil instead`);
      continue;
    }
    for (const field of IMMUTABLE) {
      if (key[field] !== old[field]) errors.push(`${name}: ${field} changed; it is immutable once published`);
    }
    const closed = old.validUntil !== null && time(old.validUntil) <= now;
    if (closed && (key.validUntil === null || time(key.validUntil) > time(old.validUntil))) {
      errors.push(`${name}: validUntil ${old.validUntil} has passed and can only be moved earlier`);
    }
  }
  if (canonical(doc.keys) !== canonical(base.keys) && time(doc.updatedAt) <= time(base.updatedAt)) {
    errors.push(`keys changed but updatedAt ${doc.updatedAt} is not after ${base.updatedAt}`);
  }
  return errors;
}

/**
 * Validates the raw contents of a key list. `base` is the raw previous version (enables the
 * change rules); `now` is the reference time for the window rules.
 * @returns {string[]} error messages, empty when the list is valid
 */
export function validate(raw, { base, now = Date.now() } = {}) {
  const doc = JSON.parse(raw);
  if (!matchesSchema(doc)) return matchesSchema.errors.map((e) => `schema: ${e.instancePath || "<root>"} ${e.message}`);
  const timestampErrors = checkTimestamps({ doc });
  if (timestampErrors.length > 0) return timestampErrors;
  const context = { raw, doc, base: base === undefined ? undefined : JSON.parse(base), now };
  return [checkFormatting, checkUpdatedAt, checkUniqueFingerprints, checkKeys, checkChanges].flatMap((rule) => rule(context));
}

/**
 * Fetches GET /info from every notary of every open-window key and compares the served key
 * with the listed one. Advisory: a mismatch is expected while a rotation is in progress.
 * @returns {Promise<string[]>} warning messages
 */
export async function checkLive(raw, { now = Date.now(), fetch = globalThis.fetch } = {}) {
  const { keys } = JSON.parse(raw);
  const checks = keys.flatMap((key, i) =>
    isOpen(key, now)
      ? key.meta.notaryUrls.map(async (url) => {
          try {
            const response = await fetch(`${url}/info`, { signal: AbortSignal.timeout(LIVE_TIMEOUT_MS) });
            if (!response.ok) return `${label(key, i)}: ${url}/info returned HTTP ${response.status}`;
            const { publicKey } = await response.json();
            return publicKey === key.publicKeyPem ? null : `${label(key, i)}: ${url}/info serves a different publicKey than publicKeyPem`;
          } catch (cause) {
            return `${label(key, i)}: ${url}/info unreachable: ${cause.message}`;
          }
        })
      : [],
  );
  return (await Promise.all(checks)).filter((warning) => warning !== null);
}
