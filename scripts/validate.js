#!/usr/bin/env node
// Usage: node scripts/validate.js [--base GIT_REF] [--live] [FILE...]
//
// Validates every notary-keys.*.json (or the given files). With --base, also enforces the
// change rules against the version of each file at that git ref. With --live, cross-checks
// open-window keys against each notary's GET /info and reports differences as warnings.
// Exits 1 if any file has errors.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { checkLive, validate } from "./rules.js";

const { values, positionals } = parseArgs({
  options: { base: { type: "string" }, live: { type: "boolean", default: false } },
  allowPositionals: true,
});
const files = positionals.length > 0 ? positionals : readdirSync(".").filter((f) => /^notary-keys\..+\.json$/.test(f));

const git = (...args) => execFileSync("git", args, { encoding: "utf8" });
// Throws if the ref is unknown, so a misconfigured base cannot silently skip the change rules.
const baseVersion = (ref, file) => (git("ls-tree", ref, "--", file) ? git("show", `${ref}:${file}`) : undefined);
const report = (level, file, message) =>
  console.log(process.env.GITHUB_ACTIONS ? `::${level} file=${file}::${message}` : `${level.toUpperCase()} ${file}: ${message}`);

let failed = false;
for (const file of files) {
  const raw = readFileSync(file, "utf8");
  const base = values.base === undefined ? undefined : baseVersion(values.base, file);
  if (values.base !== undefined && base === undefined) console.log(`${file}: not present at ${values.base}, change rules skipped`);
  const errors = validate(raw, { base });
  errors.forEach((error) => report("error", file, error));
  if (values.live && errors.length === 0) (await checkLive(raw)).forEach((warning) => report("warning", file, warning));
  console.log(`${file}: ${errors.length === 0 ? "OK" : `${errors.length} error(s)`}`);
  failed ||= errors.length > 0;
}
process.exitCode = failed ? 1 : 0;
