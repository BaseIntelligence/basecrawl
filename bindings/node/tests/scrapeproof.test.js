const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const { scrape } = require("..");

const root = path.resolve(__dirname, "../../..");
const url = "https://example.com";
const formats = ["rawHtml"];

function cliProof() {
  return JSON.parse(
    execFileSync(
      "cargo",
      [
        "run",
        "--quiet",
        "--manifest-path",
        path.join(root, "Cargo.toml"),
        "--package",
        "basecrawl-core",
        "--bin",
        "basecrawl",
        "--",
        url,
        "--formats",
        formats.join(","),
        "--output",
        "json",
      ],
      { encoding: "utf8" },
    ),
  );
}

test("scrape returns the CLI ScrapeProof shape", () => {
  const proof = scrape(url, { formats, renderEnabled: false });
  const expected = cliProof();

  assert.equal(typeof proof, "object");
  assert.deepEqual(Object.keys(proof), Object.keys(expected));
  assert.deepEqual(proof.request.formats, expected.request.formats);
  assert.equal(proof.attestation.quote, null);
  assert.equal(proof.sdk_signature.sig, null);
});
