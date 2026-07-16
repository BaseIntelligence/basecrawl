"use strict";

/**
 * VAL-NPM-003: multi-OS napi matrix is not required for M25. When only a Linux
 * prebuilt ships, package metadata and packaged docs must honestly constrain
 * platform. Smoke require + version on linux must work.
 *
 * Trusted Publishing / OIDC residuals (package_not_on_registry,
 * npm_trusted_publisher_missing) live in publish.yml; this suite asserts package
 * name + local prepack honesty and that the workflow stays on the OIDC path
 * after crates green (soft-pass typed residual rather than hard-fail crates).
 */

const assert = require("node:assert/strict");
const {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} = require("node:fs");
const { execFileSync } = require("node:child_process");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const packageRoot = path.resolve(__dirname, "..");
const packageJsonPath = path.join(packageRoot, "package.json");
const readmePath = path.join(packageRoot, "README.md");

function loadPackageJson() {
  return JSON.parse(readFileSync(packageJsonPath, "utf8"));
}

test("package name is @basecrawl/sdk", () => {
  const pkg = loadPackageJson();
  assert.equal(pkg.name, "@basecrawl/sdk");
});

test("package honestly constrains linux-x64 single-arch ship (os/cpu)", () => {
  const pkg = loadPackageJson();
  assert.ok(Array.isArray(pkg.os), "package.json must declare os[] for platform honesty");
  assert.deepEqual(pkg.os, ["linux"]);
  assert.ok(Array.isArray(pkg.cpu), "package.json must declare cpu[] for platform honesty");
  assert.deepEqual(pkg.cpu, ["x64"]);
});

test("package description and README residual renounce multi-OS without multi-OS artifacts", () => {
  const pkg = loadPackageJson();
  const description = String(pkg.description || "").toLowerCase();
  assert.match(description, /linux/, "description should mention linux");

  assert.equal(existsSync(readmePath), true, "bindings/node/README.md must exist");
  const readme = readFileSync(readmePath, "utf8");
  assert.match(readme, /linux-x64/i, "README must state linux-x64 residual");
  assert.match(readme, /not.*multi[- ]?os|single[- ]?arch|linux(?:-x64)? only/i, "README residual honesty");

  // Greppable honesty: never claim Darwin/Windows prebuilds in shipping metadata.
  for (const forbidden of ["darwin", "windows", "win32", "macos"]) {
    assert.equal(
      Array.isArray(pkg.os) && pkg.os.map((v) => String(v).toLowerCase()).includes(forbidden),
      false,
      `package.os must not claim ${forbidden} without that platform artifact`,
    );
  }
});

test("prepack produces basecrawl_sdk.node on linux and smoke require/version works", () => {
  assert.equal(process.platform, "linux", "this honesty smoke targets the linux publish host");
  assert.ok(["x64", "x86_64"].includes(process.arch) || process.arch === "x64");

  // Prefer existing artifact when already built under this workspace; otherwise build (prepack).
  const addonPath = path.join(packageRoot, "basecrawl_sdk.node");
  if (!existsSync(addonPath)) {
    execFileSync("pnpm", ["run", "prepack"], {
      cwd: packageRoot,
      encoding: "utf8",
      stdio: "pipe",
    });
  }
  assert.equal(existsSync(addonPath), true, "basecrawl_sdk.node must exist after prepack/build");

  // Smoke require/version in a child process so native teardown does not SIGSEGV
  // the node:test runner process on exit (napi + test runner interaction).
  const smokeOut = execFileSync(
    process.execPath,
    [
      "-e",
      [
        "const sdk = require('./index.js');",
        "const version = typeof sdk.version === 'function' ? sdk.version() : sdk.version;",
        "if (typeof version !== 'string' || !version) throw new Error('missing version');",
        "if (typeof sdk.scrape !== 'function') throw new Error('missing scrape');",
        "process.stdout.write('smoke version=' + version);",
      ].join("\n"),
    ],
    { cwd: packageRoot, encoding: "utf8" },
  );
  assert.match(smokeOut, /smoke version=\S+/);
});

test("npm pack includes linux native binary and honesty files; no multi-OS artifacts", () => {
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), "basecrawl-npm-honest-"));
  const packDirectory = path.join(temporaryRoot, "pack");
  mkdirSync(packDirectory);

  try {
    // Ensure prepack runs via pack (npm/pnpm pack runs lifecycle including prepack).
    execFileSync("pnpm", ["pack", "--pack-destination", packDirectory], {
      cwd: packageRoot,
      encoding: "utf8",
      stdio: "pipe",
    });

    const tarballs = readdirSync(packDirectory).filter((entry) => entry.endsWith(".tgz"));
    assert.equal(tarballs.length, 1, `expected one pack tarball, got ${JSON.stringify(tarballs)}`);

    const listing = execFileSync("tar", ["-tzf", path.join(packDirectory, tarballs[0])], {
      encoding: "utf8",
    });
    const lines = listing
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    assert.ok(
      lines.some((line) => line.endsWith("basecrawl_sdk.node") || line.includes("/basecrawl_sdk.node")),
      `pack must include basecrawl_sdk.node\n${listing}`,
    );
    assert.ok(
      lines.some((line) => line.endsWith("package.json") || line.includes("/package.json")),
      "pack must include package.json",
    );
    assert.ok(
      lines.some((line) => line.endsWith("README.md") || line.includes("/README.md")),
      "pack must include README.md residual",
    );

    // Fail if extra platform .node flavors sneak in under other names that imply multi-OS.
    const unexpected = lines.filter((line) =>
      /darwin|win32|windows|aarch64-apple|x86_64-apple|msvc/i.test(line),
    );
    assert.deepEqual(unexpected, [], `pack must not include multi-OS artifacts: ${unexpected}`);
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});

test("publish.yml uses OIDC Trusted Publishing and typed residuals after crates green", () => {
  const workflowPath = path.resolve(packageRoot, "../../.github/workflows/publish.yml");
  assert.equal(existsSync(workflowPath), true);
  const yaml = readFileSync(workflowPath, "utf8");
  assert.match(yaml, /@basecrawl\/sdk/);
  // Path A: GitHub Actions OIDC Trusted Publishing (no required bypass-2FA NPM_TOKEN).
  assert.match(yaml, /id-token:\s*write/);
  assert.match(yaml, /Trusted Publishing|OIDC/);
  assert.match(yaml, /npm@11\.5\.1|npm CLI >=?11\.5\.1|11\.5\.1\+/);
  assert.match(yaml, /node-version:\s*["']?24["']?/);
  assert.match(yaml, /registry-url:\s*["']https:\/\/registry\.npmjs\.org["']/);
  // Soft residuals when package absent or Trusted Publisher not configured.
  assert.match(yaml, /TYPED_BLOCKER=package_not_on_registry/);
  assert.match(yaml, /TYPED_BLOCKER=npm_trusted_publisher_missing/);
  assert.match(yaml, /already been published/);
  assert.match(yaml, /needs:\s*\n\s*- version-check\s*\n\s*- crates/m);
  // Live publish step must not require NODE_AUTH_TOKEN / secrets.NPM_TOKEN for OIDC path.
  // Comment/header may still name NPM_TOKEN as optional legacy; do not inject as required env.
  const livePublishBlock =
    yaml.match(/Live npm publish[\s\S]*?(?=\n\s+- name: Classify npm outcome)/) ||
    yaml.match(/npm publish --access public[\s\S]{0,2500}/);
  assert.ok(livePublishBlock, "expected live npm publish block in publish.yml");
  const liveBlock = livePublishBlock[0];
  assert.doesNotMatch(
    liveBlock,
    /NODE_AUTH_TOKEN:\s*\$\{\{\s*secrets\.NPM_TOKEN\s*\}\}/,
    "live OIDC publish must not wire secrets.NPM_TOKEN into NODE_AUTH_TOKEN",
  );
  // Never hardcode a token value pattern in the workflow.
  assert.doesNotMatch(yaml, /NODE_AUTH_TOKEN:\s*['"]?[a-zA-Z0-9_-]{20,}/);
  assert.doesNotMatch(yaml, /npm_[A-Za-z0-9]{20,}/);
});

test("operator docs mention local OTP first create and Trusted Publisher setup", () => {
  const docsPath = path.resolve(packageRoot, "../../docs/operators/install-and-publish.md");
  assert.equal(existsSync(docsPath), true);
  const docs = readFileSync(docsPath, "utf8");
  assert.match(docs, /Trusted Publishing|Trusted Publisher/);
  assert.match(docs, /OIDC|id-token/);
  assert.match(docs, /OTP|one-time|interactive/);
  assert.match(docs, /BaseIntelligence/);
  assert.match(docs, /publish\.yml/);
  assert.match(docs, /echobt1|local OTP|first package create|first-publish|first create/i);
  assert.match(docs, /package_not_on_registry|npm_trusted_publisher_missing/);
  // linux-only honesty remains; multi-OS out of scope.
  assert.match(docs, /linux-x64 only|not.*multi[- ]?os/i);
});
