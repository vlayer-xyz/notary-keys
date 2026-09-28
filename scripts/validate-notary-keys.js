#!/usr/bin/env node
// Usage: node scripts/validate-notary-keys.js [--base GIT_REF] [--live] [FILE...]
//
// Validates every notary-keys.<env>.json at the repository root (or the given files, which need
// not match that pattern). With --base, also enforces the change rules against the version of
// each file at that git ref, and fails if a list present there is missing here. With --live,
// cross-checks open-window keys against each notary's GET /info and reports differences as
// warnings. Exits 1 if anything has errors.
import { execFileSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { checkLive, validate } from "./rules.js";

const LIST_FILE = /^notary-keys\.[a-z0-9-]+\.json$/;

// GitHub workflow commands unescape these in the message; properties (file=) additionally use
// %3A and %2C.
const escape = (message) => message.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
const escapeProperty = (value) => escape(value).replaceAll(":", "%3A").replaceAll(",", "%2C");
function report(level, file, message) {
  const line = process.env.GITHUB_ACTIONS
    ? `::${level}${file === undefined ? "" : ` file=${escapeProperty(file)}`}::${escape(message)}`
    : `${level.toUpperCase()}${file === undefined ? "" : ` ${file}`}: ${message}`;
  (level === "error" ? console.error : console.log)(line);
}

let failed = false;
const fail = (file, message) => {
  report("error", file, message);
  failed = true;
};

// Anything thrown out of here is a setup problem (bad arguments, not in a git repository,
// unknown --base ref, unreadable file) and must fail the run, but as an error line rather than a
// stack trace.
try {
  const { values, positionals } = parseArgs({
    options: { base: { type: "string" }, live: { type: "boolean", default: false } },
    allowPositionals: true,
  });
  const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: "pipe" }).trim();
  const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: "pipe" });
  const lists = (names) => names.filter((name) => LIST_FILE.test(name));
  // A symlink or directory in place of a list is neither a valid list nor "still present".
  const isRegularFile = (file) => lstatSync(join(root, file), { throwIfNoEntry: false })?.isFile() === true;
  const files = positionals.length > 0 ? positionals.map((file) => relative(root, resolve(file))) : lists(readdirSync(root));
  const baseFiles =
    values.base === undefined ? [] : lists(git("ls-tree", "--name-only", "--end-of-options", values.base).split("\n"));

  if (files.length === 0) fail(undefined, `no notary-keys.<env>.json found in ${root}`);
  const removed = baseFiles.filter((file) => !isRegularFile(file));
  removed.forEach((file) => fail(file, `removed or not a regular file; key lists are never deleted or renamed`));

  for (const file of files) {
    if (removed.includes(file)) continue;
    if (!isRegularFile(file)) {
      fail(file, "not a regular file");
      continue;
    }
    const raw = readFileSync(join(root, file), "utf8");
    const base = baseFiles.includes(file) ? git("show", "--end-of-options", `${values.base}:${file}`) : undefined;
    if (values.base !== undefined && base === undefined) report("warning", file, `not present at ${values.base}; change rules skipped`);
    const errors = validate(raw, { base });
    errors.forEach((error) => fail(file, error));
    if (values.live && errors.length === 0) {
      const warnings = await checkLive(raw);
      warnings.forEach((warning) => report("warning", file, warning));
    }
    console.log(`${file}: ${errors.length === 0 ? "OK" : `${errors.length} error(s)`}`);
  }
} catch (cause) {
  fail(undefined, cause.message.trim());
}
process.exitCode = failed ? 1 : 0;
