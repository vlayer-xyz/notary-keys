import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
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
const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const bumped = (raw, patch) => `${JSON.stringify({ ...JSON.parse(raw), updatedAt: now(), ...patch }, null, 2)}\n`;
const withKey = (raw, patch) => {
  const doc = JSON.parse(raw);
  return bumped(raw, { keys: [{ ...doc.keys[0], ...patch }] });
};

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
    assert.match(stderr, /ERROR: no notary-keys\.<env>\.json found/);
  });
  it("fails on files that look like lists but are not named notary-keys.<env>.json", () => {
    for (const name of ["notary-keys.Production.json", "notary-keys.production.json.bak", "notary-keys.a,b:c.json"]) write("{", name);
    const { status, stdout, stderr } = run([]);
    assert.equal(status, 1);
    assert.equal(stderr.match(/^ERROR .*: looks like a key list but is not named notary-keys\.<env>\.json$/gm).length, 3, stderr);
    assert.match(stdout, new RegExp(`^${FILE}: OK$`, "m"));
  });
  it("ignores unrelated files", () => {
    write("{", "keys.json");
    const { status, stdout } = run([]);
    assert.equal(status, 0, stdout);
  });
  it("fails on a list that is a directory or a symlink", () => {
    mkdirSync(join(repo, "notary-keys.dir.json"));
    write("{}", "elsewhere.json");
    symlinkSync("elsewhere.json", join(repo, "notary-keys.link.json"));
    const { status, stdout, stderr } = run([]);
    assert.equal(status, 1);
    assert.match(stderr, /^ERROR notary-keys\.dir\.json: not a regular file$/m);
    assert.match(stderr, /^ERROR notary-keys\.link\.json: not a regular file$/m);
    assert.match(stdout, new RegExp(`^${FILE}: OK$`, "m"));
  });
  it("fails when a list present at --base was replaced by a symlink, even if another list was added", () => {
    write(production, "notary-keys.other.json");
    unlinkSync(join(repo, FILE));
    symlinkSync("notary-keys.other.json", join(repo, FILE));
    const { status, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR ${FILE}: removed or not a regular file; key lists are never deleted or renamed$`, "m"));
    assert.equal(stderr.match(/^ERROR/gm).length, 1, stderr);
  });
  it("fails with an error line, not a stack trace, for a missing positional file", () => {
    const { status, stderr } = run(["no-such.json"]);
    assert.equal(status, 1);
    assert.match(stderr, /^ERROR no-such\.json: not a regular file$/m);
    assert.doesNotMatch(stderr, /^\s+at /m);
  });
  it("fails with an error line for bad arguments", () => {
    const { status, stderr } = run(["--nope"]);
    assert.equal(status, 1);
    assert.match(stderr, /^ERROR: Unknown option '--nope'/m);
    assert.doesNotMatch(stderr, /^\s+at /m);
  });
  it("escapes the file name in annotations", () => {
    write("{", "list,a:b.json");
    const { stderr } = run(["list,a:b.json"], { annotations: true });
    assert.match(stderr, /^::error file=list%2Ca%3Ab\.json::file is not valid JSON/m);
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
    write(withKey(production, { validFrom: "2024-11-27T00:00:00Z" }));
    assert.equal(run([]).status, 0);
    const { status, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR ${FILE}: keys\\[0\\] .*: validFrom changed; it is immutable once published$`, "m"));
  });
  it("probes the notaries with --live and reports them as warnings", () => {
    write(withKey(production, { meta: { notaryUrls: ["https://127.0.0.1:1"] } }));
    const { status, stdout } = run(["--live"], { annotations: true });
    assert.equal(status, 0, stdout);
    assert.match(stdout, new RegExp(`^::warning file=${FILE}::keys\\[0\\] .*: https://127\\.0\\.0\\.1:1/info unreachable: `, "m"));
    assert.doesNotMatch(run([]).stdout, /warning/);
  });
  it("fails loudly on an unknown base ref", () => {
    const { status, stderr } = run(["--base", "no-such-ref"]);
    assert.equal(status, 1);
    assert.match(stderr, /^ERROR: Command failed: git ls-tree .*no-such-ref/m);
    assert.doesNotMatch(stderr, /^\s+at /m);
  });
  it("fails loudly on the all-zeros base of a newly created branch", () => {
    const { status, stderr } = run(["--base", "0".repeat(40)]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR: Command failed: git ls-tree .*${"0".repeat(40)}`, "m"));
  });
  it("treats a list that was a symlink at --base as absent there", () => {
    write(production, "real.json");
    unlinkSync(join(repo, FILE));
    symlinkSync("real.json", join(repo, FILE));
    git("add", "-A");
    git("commit", "-q", "-m", "symlink");
    unlinkSync(join(repo, FILE));
    write(production);
    const { status, stdout } = run(["--base", "HEAD"]);
    assert.equal(status, 0, stdout);
    assert.match(stdout, new RegExp(`^WARNING ${FILE}: not present at HEAD; change rules skipped$`, "m"));
  });
  it("fails when a list present at --base was deleted", () => {
    unlinkSync(join(repo, FILE));
    write(production, "notary-keys.other.json");
    const { status, stderr } = run(["--base", "HEAD"]);
    assert.equal(status, 1);
    assert.match(stderr, new RegExp(`^ERROR ${FILE}: removed or not a regular file; key lists are never deleted or renamed$`, "m"));
  });
  it("rejects a --base that looks like a git option", () => {
    const { status, stderr } = run(["--base=-r"]);
    assert.equal(status, 1);
    assert.match(stderr, /^ERROR: Command failed: git ls-tree --end-of-options -r$/m);
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
