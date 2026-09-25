#!/usr/bin/env node
/**
 * Validate a notary key list.
 *
 *     node scripts/validate.ts FILE [--base BASE_FILE] [--live]
 *
 * Checks the file against schema.json and the invariants the schema cannot
 * express (fingerprint derivation, window ordering, canonical formatting).
 * With --base, also enforces the change rules against the previous version of
 * the list. With --live, fetches GET /info from every notary of every
 * open-window key and compares the served key with the listed one.
 *
 * Exits 0 when every check passes, 1 otherwise. Findings are printed one per
 * line as `ERROR: ...` or `WARN: ...`.
 */

import { createHash, createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Ajv2020 } from "ajv/dist/2020.js";

const SCHEMA_PATH = new URL("../schema.json", import.meta.url);
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;
const LIVE_TIMEOUT_MS = 15_000;
const COMPRESSED_POINT_BYTES = 33;

// node:crypto reports OpenSSL curve names; the list uses SEC 2 names.
const CURVE_NAMES: Record<string, string> = {
  secp256k1: "secp256k1",
  prime256v1: "secp256r1",
};

interface NotaryKey {
  fingerprint: string;
  publicKeyPem: string;
  curve: string;
  validFrom: string;
  validUntil: string | null;
  meta: { notaryUrls: string[] };
}

interface KeyList {
  schemaVersion: number;
  updatedAt: string;
  fingerprintAlgorithm: string;
  keys: NotaryKey[];
}

const findings = { errors: 0, warnings: 0 };

function error(message: string): void {
  findings.errors += 1;
  console.log(`ERROR: ${message}`);
}

function warn(message: string): void {
  findings.warnings += 1;
  console.log(`WARN: ${message}`);
}

function parseTimestamp(value: string): Date {
  const date = new Date(value);
  const roundTrip = date.toISOString().replace(/\.\d{3}Z$/, "Z");
  if (!TIMESTAMP_PATTERN.test(value) || roundTrip !== value) {
    throw new Error(`invalid timestamp ${value}`);
  }
  return date;
}

function canonicalJson(document: unknown): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

function load(path: string): { raw: string; document: KeyList } {
  const raw = readFileSync(path, "utf8");
  return { raw, document: JSON.parse(raw) as KeyList };
}

function checkSchema(document: unknown): boolean {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
  const ajv = new Ajv2020({ allErrors: true });
  const validate = ajv.compile(schema);
  if (validate(document)) return true;
  for (const problem of validate.errors ?? []) {
    error(`schema: ${problem.instancePath || "<root>"}: ${problem.message ?? "invalid"}`);
  }
  return false;
}

/** The schema only checks the shape of timestamps; this checks they denote real instants. */
function checkTimestamps(document: KeyList): boolean {
  const fields: Array<[string, string]> = [["updatedAt", document.updatedAt]];
  document.keys.forEach((key, index) => {
    fields.push([`keys[${index}].validFrom`, key.validFrom]);
    if (key.validUntil !== null) fields.push([`keys[${index}].validUntil`, key.validUntil]);
  });
  let valid = true;
  for (const [path, value] of fields) {
    try {
      parseTimestamp(value);
    } catch {
      error(`${path}: ${value} is not a valid UTC instant`);
      valid = false;
    }
  }
  return valid;
}

function checkFormatting(raw: string, document: KeyList): void {
  if (raw !== canonicalJson(document)) {
    error(
      "file is not canonically formatted; regenerate with " +
        "`node -e 'const f=process.argv[1],fs=require(\"fs\");fs.writeFileSync(f,JSON.stringify(JSON.parse(fs.readFileSync(f,\"utf8\")),null,2)+\"\\n\")' FILE`",
    );
  }
}

function checkUpdatedAtNotInFuture(document: KeyList): void {
  const updatedAt = parseTimestamp(document.updatedAt);
  if (updatedAt.getTime() > Date.now() + CLOCK_SKEW_MS) {
    error(`updatedAt ${document.updatedAt} is more than 24h in the future`);
  }
}

function compressedPoint(pem: string): { curve: string; point: Buffer; der: Buffer } {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ec") {
    throw new Error(`not an EC key (${key.asymmetricKeyType})`);
  }
  const opensslCurve = key.asymmetricKeyDetails?.namedCurve ?? "";
  const curve = CURVE_NAMES[opensslCurve];
  if (curve === undefined) {
    throw new Error(`unsupported curve ${opensslCurve}`);
  }
  const jwk = key.export({ format: "jwk" });
  const x = Buffer.from(jwk.x as string, "base64url");
  const y = Buffer.from(jwk.y as string, "base64url");
  const prefix = 0x02 + (y[y.length - 1]! & 1);
  const point = Buffer.concat([Buffer.from([prefix]), x]);
  const der = Buffer.from(
    pem
      .split("\n")
      .filter((line) => !line.startsWith("-----"))
      .join(""),
    "base64",
  );
  return { curve, point, der };
}

function checkKey(key: NotaryKey, index: number): void {
  const label = `keys[${index}] (${key.fingerprint.slice(0, 12)}…)`;

  let parsed: ReturnType<typeof compressedPoint>;
  try {
    parsed = compressedPoint(key.publicKeyPem);
  } catch (cause) {
    error(`${label}: publicKeyPem does not parse: ${(cause as Error).message}`);
    return;
  }

  if (parsed.curve !== key.curve) {
    error(`${label}: curve is ${key.curve} but publicKeyPem is ${parsed.curve}`);
  }

  const fingerprint = createHash("sha256").update(parsed.point).digest("hex");
  if (fingerprint !== key.fingerprint) {
    error(`${label}: fingerprint is ${key.fingerprint} but sha256(compressed point) is ${fingerprint}`);
  }

  if (!parsed.der.subarray(-COMPRESSED_POINT_BYTES).equals(parsed.point)) {
    error(
      `${label}: publicKeyPem must encode the point in compressed form ` +
        "(as returned by the notary's GET /info), not uncompressed",
    );
  }

  const validFrom = parseTimestamp(key.validFrom);
  if (key.validUntil !== null) {
    const validUntil = parseTimestamp(key.validUntil);
    if (validUntil <= validFrom) {
      error(`${label}: validUntil ${key.validUntil} is not after validFrom ${key.validFrom}`);
    }
  }
}

function checkUniqueFingerprints(document: KeyList): void {
  const seen = new Map<string, number>();
  document.keys.forEach((key, index) => {
    const first = seen.get(key.fingerprint);
    if (first !== undefined) {
      error(`keys[${index}]: duplicate fingerprint, first seen at keys[${first}]`);
    } else {
      seen.set(key.fingerprint, index);
    }
  });
}

/**
 * Change rules: entries are append-only, identity fields are immutable, an
 * already-closed window may only be shortened, and any change to `keys` bumps
 * `updatedAt`.
 */
function checkAgainstBase(document: KeyList, base: KeyList): void {
  const now = Date.now();
  const headByFingerprint = new Map(document.keys.map((key) => [key.fingerprint, key]));

  for (const old of base.keys) {
    const label = `key ${old.fingerprint.slice(0, 12)}…`;
    const current = headByFingerprint.get(old.fingerprint);
    if (current === undefined) {
      error(`${label}: removed; entries are never deleted, set validUntil instead`);
      continue;
    }
    for (const field of ["publicKeyPem", "curve", "validFrom"] as const) {
      if (current[field] !== old[field]) {
        error(`${label}: ${field} changed; it is immutable once published`);
      }
    }
    if (old.validUntil !== null && current.validUntil !== old.validUntil) {
      const oldUntil = parseTimestamp(old.validUntil);
      if (oldUntil.getTime() <= now) {
        if (current.validUntil === null) {
          error(`${label}: validUntil ${old.validUntil} has passed and cannot be reopened`);
        } else if (parseTimestamp(current.validUntil) > oldUntil) {
          error(`${label}: validUntil ${old.validUntil} has passed and can only be moved earlier`);
        }
      }
    }
  }

  if (canonicalJson(document.keys) !== canonicalJson(base.keys)) {
    if (parseTimestamp(document.updatedAt) <= parseTimestamp(base.updatedAt)) {
      error(`keys changed but updatedAt ${document.updatedAt} is not after ${base.updatedAt}`);
    }
  }
}

async function fetchInfoPublicKey(url: string): Promise<string> {
  const response = await fetch(`${url.replace(/\/+$/, "")}/info`, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(LIVE_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const body = (await response.json()) as { publicKey?: unknown };
  if (typeof body.publicKey !== "string") {
    throw new Error("response has no publicKey string");
  }
  return body.publicKey;
}

async function checkLive(document: KeyList): Promise<void> {
  const now = Date.now();
  for (const [index, key] of document.keys.entries()) {
    if (key.validUntil !== null && parseTimestamp(key.validUntil).getTime() <= now) continue;
    const label = `keys[${index}] (${key.fingerprint.slice(0, 12)}…)`;
    for (const url of key.meta.notaryUrls) {
      let served: string;
      try {
        served = await fetchInfoPublicKey(url);
      } catch (cause) {
        warn(`${label}: ${url}/info unreachable: ${(cause as Error).message}`);
        continue;
      }
      if (served === key.publicKeyPem) {
        console.log(`OK: ${label}: ${url}/info serves the listed key`);
      } else {
        error(`${label}: ${url}/info serves a different publicKey than publicKeyPem`);
      }
    }
  }
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    options: {
      base: { type: "string" },
      live: { type: "boolean", default: false },
    },
    allowPositionals: true,
  });
  const file = positionals[0];
  if (file === undefined || positionals.length !== 1) {
    console.error("usage: validate.ts FILE [--base BASE_FILE] [--live]");
    return 2;
  }

  const { raw, document } = load(file);
  if (!checkSchema(document) || !checkTimestamps(document)) return 1;
  checkFormatting(raw, document);
  checkUpdatedAtNotInFuture(document);
  checkUniqueFingerprints(document);
  document.keys.forEach(checkKey);

  if (values.base !== undefined) {
    if (existsSync(values.base)) {
      const { document: base } = load(values.base);
      if (checkSchema(base) && checkTimestamps(base)) {
        checkAgainstBase(document, base);
      } else {
        warn(`base ${values.base} does not validate; change rules skipped`);
      }
    } else {
      console.log(`OK: no base version at ${values.base}; change rules skipped (new file)`);
    }
  }

  if (values.live) {
    await checkLive(document);
  }

  console.log(`${file}: ${findings.errors} error(s), ${findings.warnings} warning(s)`);
  return findings.errors > 0 ? 1 : 0;
}

process.exitCode = await main();
