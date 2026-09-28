#!/usr/bin/env node
// Usage: node scripts/validate-notary-keys.js [--base GIT_REF] [--live] [FILE...]
//
// Validates every notary-keys.*.json at the repository root (or the given files). With --base,
// also enforces the change rules against the version of each file at that git ref, and fails if
// a list present there is missing here. With --live, cross-checks open-window keys against each
// notary's GET /info and reports differences as warnings. Exits 1 if anything has errors.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { checkLive, validate } from "./rules.js";

const LIST_FILE = /^notary-keys\..+\.json$/;

const { values, positionals } = parseArgs({
  options: { base: { type: "string" }, live: { type: "boolean", default: false } },
  allowPositionals: true,
});

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
// Throws if the ref is unknown, so a misconfigured base cannot silently skip the change rules.
const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8" });
const lists = (names) => names.filter((name) => LIST_FILE.test(name));
const files = positionals.length > 0 ? positionals.map((file) => relative(root, resolve(file))) : lists(readdirSync(root));
const baseFiles = values.base === undefined ? [] : lists(git("ls-tree", "--name-only", values.base).split("\n"));

const escape = (message) => message.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
function report(level, file, message) {
  const line = process.env.GITHUB_ACTIONS
    ? `::${level}${file === undefined ? "" : ` file=${file}`}::${escape(message)}`
    : `${level.toUpperCase()}${file === undefined ? "" : ` ${file}`}: ${message}`;
  (level === "error" ? console.error : console.log)(line);
}

let failed = false;
const fail = (file, message) => {
  report("error", file, message);
  failed = true;
};

if (files.length === 0) fail(undefined, `no notary-keys.*.json found in ${root}`);
for (const file of baseFiles) {
  if (!existsSync(join(root, file))) fail(file, `removed; key lists are never deleted or renamed`);
}

for (const file of files) {
  const raw = readFileSync(join(root, file), "utf8");
  const base = baseFiles.includes(file) ? git("show", `${values.base}:${file}`) : undefined;
  if (values.base !== undefined && base === undefined) report("warning", file, `not present at ${values.base}; change rules skipped`);
  const errors = validate(raw, { base });
  errors.forEach((error) => fail(file, error));
  if (values.live && errors.length === 0) {
    const warnings = await checkLive(raw);
    warnings.forEach((warning) => report("warning", file, warning));
  }
  console.log(`${file}: ${errors.length === 0 ? "OK" : `${errors.length} error(s)`}`);
}
process.exitCode = failed ? 1 : 0;
