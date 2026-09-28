import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, it } from "node:test";

const script = fileURLToPath(new URL("./validate-notary-keys.js", import.meta.url));
const production = readFileSync(new URL("../notary-keys.production.json", import.meta.url), "utf8");
const FILE = "notary-keys.test.json";

// Each test runs the CLI in a throwaway git repository whose only list is a copy of the
// committed one, committed at HEAD.
let repo;
const git = (...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args], { cwd: repo, encoding: "utf8" });
const write = (contents, file = FILE) => writeFileSync(join(repo, file), contents);
const run = (args, { annotations = false, cwd = repo } = {}) => {
  const env = { ...process.env };
  if (annotations) env.GITHUB_ACTIONS = "true";
  else delete env.GITHUB_ACTIONS;
  return spawnSync(process.execPath, [script, ...args], { cwd, env, encoding: "utf8" });
};
const bumped = (raw, patch) => `${JSON.stringify({ ...JSON.parse(raw), updatedAt: "2030-01-01T00:00:00Z", ...patch }, null, 2)}\n`;

beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), "notary-keys-"));
  git("init", "-q", "-b", "main");
  write(production);
  git("add", "-A");
  git("commit", "-q", "-m", "seed");
});
afterEach(() => rmSync(repo, { recursive: true, force: true }));

describe("validate-notary-keys CLI", () => {
  it("passes a valid list", () => {
    const { status, stdout } = run(["--base", "HEAD"]);
    assert.equal(status, 0, stdout);
    assert.match(stdout, new RegExp(`^${FILE}: OK$`, "m"));
  });
  it("discovers lists from the repository root when run from a subdirectory", () => {
    mkdirSync(join(repo, "sub"));
    const { status, stdout } = run([], { cwd: join(repo, "sub") });
    assert.equal(status, 0, stdout);
    assert.match(stdout, new RegExp(`^${FILE}: OK$`, "m"));
  });
  it("fails when no list is found", () => {
    unlinkSync(join(repo, FILE));
    const { status, stderr } = run([]);
    assert.equal(status, 1);
    assert.match(stderr, /ERROR: no notary-keys\.\*\.json found/);
  });
  it("reports errors as GitHub annotations and exits 1", () => {
    write(JSON.stringify(JSON.parse(production)));
    const { status, stdout, stderr } = run([], { annotations: true });
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^::error file=${FILE}::file is not canonically formatted`, "m"));
    assert.match(stdout, new RegExp(`^${FILE}: 1 error\\(s\\)$`, "m"));
  });
  it("escapes newlines in annotation messages", () => {
    write("{\n\n");
    const { stderr } = run([], { annotations: true });
    assert.match(stderr, /^::error file=.*::file is not valid JSON: [^\n]*$/m);
  });
  it("enforces the change rules against --base", () => {
    write(bumped(production, { keys: [] }));
    const { status, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, /must NOT have fewer than 1 items/);
  });
  it("fails loudly on an unknown base ref", () => {
    const { status, stderr } = run(["--base", "no-such-ref"]);
    assert.notEqual(status, 0);
    assert.match(stderr, /no-such-ref/);
  });
  it("fails when a list present at --base was deleted", () => {
    unlinkSync(join(repo, FILE));
    write(production, "notary-keys.other.json");
    const { status, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR ${FILE}: removed; key lists are never deleted or renamed$`, "m"));
  });
  it("fails when a list was renamed, and only warns for the new name", () => {
    renameSync(join(repo, FILE), join(repo, "notary-keys.renamed.json"));
    const { status, stdout, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR ${FILE}: removed`, "m"));
    assert.match(stdout, /^WARNING notary-keys\.renamed\.json: not present at HEAD; change rules skipped$/m);
  });
  it("validates only the given files but still detects deletions", () => {
    write(production, "notary-keys.other.json");
    git("add", "-A");
    git("commit", "-q", "-m", "second list");
    unlinkSync(join(repo, "notary-keys.other.json"));
    const { status, stdout, stderr } = run(["--base", "HEAD", FILE]);
    assert.equal(status, 1);
    assert.match(stdout, new RegExp(`^${FILE}: OK$`, "m"));
    assert.match(stderr, /^ERROR notary-keys\.other\.json: removed/m);
  });
});
