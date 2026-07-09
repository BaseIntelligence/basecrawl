const assert = require("node:assert/strict");
const { execFileSync, spawn, spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const { scrape, version } = require("..");

const root = path.resolve(__dirname, "../../..");
const exampleOptions = {
  formats: ["markdown", "links", "metadata"],
  renderEnabled: false,
};
const quoteOptions = {
  formats: ["markdown", "links"],
  renderEnabled: false,
};

function cliProof(url, formats) {
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
        "--no-js",
        "--output",
        "json",
      ],
      { encoding: "utf8" },
    ),
  );
}

function cliRun(url, formats) {
  const args = [
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
    "--no-js",
    "--output",
    "json",
  ];
  if (formats !== undefined) {
    args.push("--formats", formats.join(","));
  }
  return spawnSync("cargo", args, { encoding: "utf8" });
}

function canonicalWire(proof) {
  return JSON.stringify(proof);
}

function withoutVolatileFields(proof) {
  const normalized = structuredClone(proof);
  delete normalized.egress.timestamp;
  delete normalized.egress.egress_ip;
  delete normalized.tls.handshake_transcript_hash;
  delete normalized.tls.server_ephemeral_pubkey;
  delete normalized.response.headers_hash;
  return normalized;
}

function startStaticFixture() {
  const script = [
    'const http = require("node:http");',
    'const body = "<!doctype html><html><title>Parity</title><body>same bytes</body></html>";',
    "http.createServer((_, response) => {",
    '  response.writeHead(200, {"Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(body), Connection: "close"});',
    "  response.end(body);",
    '}).listen(21092, "127.0.0.1", function () { console.log(this.address().port); });',
  ].join("\n");

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    child.stdout.once("data", (chunk) => {
      resolve({
        url: `http://127.0.0.1:${chunk.toString().trim()}/`,
        stop: () => child.kill(),
      });
    });
    child.once("exit", (code) => {
      if (code !== 0 && stderr) {
        reject(new Error(`static fixture exited ${code}: ${stderr}`));
      }
    });
  });
}

test("Node matches CLI content digests and outputs", () => {
  const nodeExample = scrape("https://example.com", exampleOptions);
  const cliExample = cliProof("https://example.com", exampleOptions.formats);

  assert.equal(nodeExample.result.result_hash, cliExample.result.result_hash);
  assert.equal(nodeExample.tls.cert_chain_hash, cliExample.tls.cert_chain_hash);

  const nodeQuotes = scrape("https://quotes.toscrape.com", quoteOptions);
  const cliQuotes = cliProof("https://quotes.toscrape.com", quoteOptions.formats);

  assert.equal(
    nodeQuotes.result.formats_produced.markdown,
    cliQuotes.result.formats_produced.markdown,
  );
  assert.deepEqual(nodeQuotes.result.formats_produced.links, cliQuotes.result.formats_produced.links);
});

test("Node and CLI emit byte-identical canonical JSON after volatile fields are removed", async () => {
  const fixture = await startStaticFixture();
  try {
    const nodeProof = scrape(fixture.url, {
      formats: ["rawHtml"],
      renderEnabled: false,
    });
    const cli = cliRun(fixture.url, ["rawHtml"]);

    assert.equal(cli.status, 0, cli.stderr);
    assert.equal(
      canonicalWire(withoutVolatileFields(nodeProof)),
      canonicalWire(withoutVolatileFields(JSON.parse(cli.stdout))),
    );
  } finally {
    fixture.stop();
  }
});

test("Node and CLI normalize format selection identically", async () => {
  const fixture = await startStaticFixture();
  try {
    for (const formats of [
      undefined,
      ["metadata", "rawHtml", "metadata"],
      ["rawHtml"],
    ]) {
      const options = { renderEnabled: false };
      if (formats !== undefined) {
        options.formats = formats;
      }

      const nodeProof = scrape(fixture.url, options);
      const cli = cliRun(fixture.url, formats);

      assert.equal(cli.status, 0, cli.stderr);
      const cliProof = JSON.parse(cli.stdout);
      assert.deepEqual(nodeProof.request.formats, cliProof.request.formats);
      assert.deepEqual(
        Object.keys(nodeProof.result.formats_produced),
        Object.keys(cliProof.result.formats_produced),
      );
    }
  } finally {
    fixture.stop();
  }
});

test("Node and CLI reject invalid input without a partial ScrapeProof", () => {
  for (const [url, formats, expectedKind] of [
    ["not a url", ["rawHtml"], "invalid_url"],
    ["https://example.com", ["bogusfmt"], "invalid_format"],
  ]) {
    const cli = cliRun(url, formats);
    assert.notEqual(cli.status, 0);
    assert.equal(cli.stdout, "");
    assert.equal(JSON.parse(cli.stderr).error.kind, expectedKind);

    assert.throws(
      () => scrape(url, { formats }),
      (error) => JSON.parse(error.message).error.kind === expectedKind,
    );
  }
});

test("Node version matches the CLI version", () => {
  const cliVersion = execFileSync(
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
      "--version",
    ],
    { encoding: "utf8" },
  ).trim();

  assert.equal(cliVersion, `basecrawl ${version()}`);
});
