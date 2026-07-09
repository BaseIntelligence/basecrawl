"""Black-box canonical-wire and behavior parity checks for every M1 SDK binding."""

import argparse
import json
import multiprocessing
import subprocess
import sys
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class StaticHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    body = b"<!doctype html><html><title>Parity</title><body>same bytes</body></html>"

    def do_GET(self) -> None:  # noqa: N802
        self.send_response_only(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, cwd=cwd, text=True)


def parse_success(result: subprocess.CompletedProcess[str], binding: str) -> dict[str, object]:
    if result.returncode != 0:
        raise AssertionError(f"{binding} scrape failed: {result.stderr}")
    if not result.stdout:
        raise AssertionError(f"{binding} emitted no ScrapeProof")
    return json.loads(result.stdout)


def canonical_without_volatile_fields(proof: dict[str, object]) -> str:
    normalized = deepcopy(proof)
    normalized["egress"].pop("timestamp")
    normalized["egress"].pop("egress_ip")
    normalized["tls"].pop("handshake_transcript_hash")
    normalized["tls"].pop("server_ephemeral_pubkey")
    normalized["response"].pop("headers_hash")
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def assert_error(
    result: subprocess.CompletedProcess[str], binding: str, expected_kind: str
) -> None:
    if result.returncode == 0:
        raise AssertionError(f"{binding} unexpectedly accepted invalid input")
    if result.stdout:
        raise AssertionError(f"{binding} emitted a partial ScrapeProof: {result.stdout}")
    if json.loads(result.stderr)["error"]["kind"] != expected_kind:
        raise AssertionError(f"{binding} did not report {expected_kind}: {result.stderr}")


def serve_static_fixture(port_queue) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 21093), StaticHandler)
    port_queue.put(server.server_port)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--c-program", type=Path, required=True)
    parser.add_argument("--node-dir", type=Path, required=True)
    args = parser.parse_args()

    port_queue = multiprocessing.Queue()
    server_process = multiprocessing.Process(
        target=serve_static_fixture,
        args=(port_queue,),
        daemon=True,
    )
    server_process.start()
    url = f"http://127.0.0.1:{port_queue.get(timeout=5)}/"
    formats = ["metadata", "rawHtml", "metadata"]
    options_json = json.dumps({"formats": formats, "renderEnabled": False})
    try:
        proofs = {
            "CLI": parse_success(
                run(
                    [
                        str(args.cli),
                        url,
                        "--formats",
                        ",".join(formats),
                        "--no-js",
                        "--output",
                        "json",
                    ]
                ),
                "CLI",
            ),
            "Python": parse_success(
                run(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import basecrawl,json,sys;"
                            "print(json.dumps(basecrawl.scrape(sys.argv[1], "
                            "{'formats':['metadata','rawHtml','metadata'],"
                            "'render_enabled':False}), ensure_ascii=False,separators=(',',':')))"
                        ),
                        url,
                    ]
                ),
                "Python",
            ),
            "Node": parse_success(
                run(
                    [
                        "node",
                        "-e",
                        (
                            "const sdk=require('.');"
                            "console.log(JSON.stringify(sdk.scrape(process.argv[1],"
                            "{formats:['metadata','rawHtml','metadata'],renderEnabled:false})));"
                        ),
                        url,
                    ],
                    cwd=args.node_dir,
                ),
                "Node",
            ),
            "C": parse_success(
                run([str(args.c_program), url, "--options", options_json]),
                "C",
            ),
        }
    finally:
        server_process.terminate()
        server_process.join(timeout=5)

    canonical_wires = {
        name: canonical_without_volatile_fields(proof) for name, proof in proofs.items()
    }
    if len(set(canonical_wires.values())) != 1:
        raise AssertionError(f"canonical wires differ: {canonical_wires}")

    expected_keys = ["metadata", "rawHtml"]
    for name, proof in proofs.items():
        if list(proof["result"]["formats_produced"]) != expected_keys:
            raise AssertionError(f"{name} produced unexpected formats: {proof}")

    invalid_cases = [
        ("not a url", ["rawHtml"], "invalid_url"),
        ("https://example.com", ["bogusfmt"], "invalid_format"),
    ]
    for invalid_url, invalid_formats, expected_kind in invalid_cases:
        assert_error(
            run(
                [
                    str(args.cli),
                    invalid_url,
                    "--formats",
                    ",".join(invalid_formats),
                    "--no-js",
                    "--output",
                    "json",
                ]
            ),
            "CLI",
            expected_kind,
        )
        assert_error(
            run(
                [
                    sys.executable,
                    "-c",
                    "\n".join(
                        [
                            "import basecrawl, json, sys",
                            "try:",
                            "    basecrawl.scrape(sys.argv[1], {'formats': json.loads(sys.argv[2])})",
                            "except ValueError as error:",
                            "    print(error, file=sys.stderr)",
                            "    sys.exit(1)",
                            "raise SystemExit('expected ValueError')",
                        ]
                    ),
                    invalid_url,
                    json.dumps(invalid_formats),
                ]
            ),
            "Python",
            expected_kind,
        )
        assert_error(
            run(
                [
                    "node",
                    "-e",
                    (
                        "const sdk=require('.');"
                        "try { sdk.scrape(process.argv[1], {formats:JSON.parse(process.argv[2])}); }"
                        "catch (error) { console.error(error.message); process.exit(1); }"
                        "process.exit(20);"
                    ),
                    invalid_url,
                    json.dumps(invalid_formats),
                ],
                cwd=args.node_dir,
            ),
            "Node",
            expected_kind,
        )
        assert_error(
            run(
                [
                    str(args.c_program),
                    invalid_url,
                    "--options",
                    json.dumps({"formats": invalid_formats, "renderEnabled": False}),
                ]
            ),
            "C",
            expected_kind,
        )

    versions = {
        "CLI": run([str(args.cli), "--version"]).stdout.strip().removeprefix("basecrawl "),
        "Python": run(
            [sys.executable, "-c", "import basecrawl; print(basecrawl.__version__)"]
        ).stdout.strip(),
        "Node": run(["node", "-e", "console.log(require('.').version())"], cwd=args.node_dir)
        .stdout.strip(),
        "C": run([str(args.c_program), "--version"]).stdout.strip(),
    }
    if len(set(versions.values())) != 1:
        raise AssertionError(f"binding versions differ: {versions}")


if __name__ == "__main__":
    main()
