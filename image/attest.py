"""Fail-closed dstack GetQuote client and real-CVM attestation harness.

The quote signing key never exists in this process.  ``request_quote`` talks to the Unix socket
mounted inside a CVM; ``hand_assembled_quote`` exists only to exercise the negative verifier path
and deliberately contains no signature or certification data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

MIN_QUOTE_LEN = 48 + 520 + 64
MIN_QUOTE_HEX_LEN = MIN_QUOTE_LEN * 2
SOCKET_PATH = Path("/var/run/dstack.sock")
REPORT_DATA_BYTES = 64
QUOTE_HEADER_BYTES = 48
TD_REPORT_DATA_OFFSET = 520
TD_REPORT_DATA_BYTES = 64


class AttestationError(RuntimeError):
    """A quote response failed closed validation."""


def normalize_report_data(report_data: str) -> str:
    value = report_data.strip().lower()
    if (
        not value
        or len(value) % 2
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise AttestationError("report_data must be non-empty, even-length hexadecimal")
    payload = bytes.fromhex(value)
    if len(payload) > REPORT_DATA_BYTES:
        payload = hashlib.sha256(payload).digest()
    return payload.ljust(REPORT_DATA_BYTES, b"\0").hex()


def _quote_shape(quote_hex: str, report_data: str) -> None:
    if (
        len(quote_hex) < MIN_QUOTE_HEX_LEN
        or len(quote_hex) % 2
        or any(char not in "0123456789abcdef" for char in quote_hex)
    ):
        raise AttestationError("quote is missing, malformed, or truncated")
    quote = bytes.fromhex(quote_hex)
    if (
        len(quote) < QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET + TD_REPORT_DATA_BYTES
        or int.from_bytes(quote[0:2], "little") != 4
        or int.from_bytes(quote[4:8], "little") != 0x81
    ):
        raise AttestationError("quote is not an Intel TDX v4 quote")
    embedded = quote[
        QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET : QUOTE_HEADER_BYTES
        + TD_REPORT_DATA_OFFSET
        + TD_REPORT_DATA_BYTES
    ].hex()
    if embedded != report_data:
        raise AttestationError("quote report_data does not match submitted report_data")


def parse_get_quote(payload: str | bytes, submitted_report_data: str) -> dict[str, Any]:
    expected = normalize_report_data(submitted_report_data)
    try:
        response = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise AttestationError(f"GetQuote returned invalid JSON: {error}") from error
    if not isinstance(response, dict):
        raise AttestationError("GetQuote response must be a JSON object")
    for field in ("quote", "event_log", "report_data", "vm_config"):
        if field not in response or response[field] in (None, "", [], {}):
            raise AttestationError(f"GetQuote response is missing {field}")
    returned = response["report_data"]
    if not isinstance(returned, str) or normalize_report_data(returned) != expected:
        raise AttestationError(
            "GetQuote response report_data does not match submitted value"
        )
    quote = response["quote"]
    if not isinstance(quote, str):
        raise AttestationError("GetQuote quote must be hexadecimal text")
    quote = quote.lower()
    _quote_shape(quote, expected)
    response["quote"] = quote
    response["report_data"] = expected
    return response


def _http_post_unix(path: Path, body: bytes, timeout: float) -> bytes:
    request = (
        b"POST /GetQuote HTTP/1.1\r\n"
        b"Host: dstack\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
            client.sendall(request)
            chunks: list[bytes] = []
            while chunk := client.recv(64 * 1024):
                chunks.append(chunk)
    except OSError as error:
        raise AttestationError(
            f"dstack guest-agent socket unavailable: {error}"
        ) from error
    response = b"".join(chunks)
    separator = response.find(b"\r\n\r\n")
    if separator < 0:
        raise AttestationError("GetQuote returned an incomplete HTTP response")
    status_line = response.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2:
        raise AttestationError("GetQuote returned an invalid HTTP status")
    try:
        status = int(status_line[1])
    except ValueError as error:
        raise AttestationError("GetQuote returned an invalid HTTP status") from error
    if status != 200:
        raise AttestationError(f"GetQuote returned HTTP {status}")
    return response[separator + 4 :]


def request_quote(
    report_data: str,
    *,
    socket_path: Path = SOCKET_PATH,
    timeout: float = 10.0,
) -> dict[str, Any]:
    expected = normalize_report_data(report_data)
    payload = json.dumps({"report_data": expected}, separators=(",", ":")).encode()
    return parse_get_quote(_http_post_unix(socket_path, payload, timeout), expected)


def hand_assembled_quote(report_data: str) -> str:
    """Build an intentionally unsigned v4-shaped value for negative testing only."""

    expected = normalize_report_data(report_data)
    quote = bytearray(QUOTE_HEADER_BYTES + 584 + 64)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[4:8] = (0x81).to_bytes(4, "little")
    quote[
        QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET : QUOTE_HEADER_BYTES
        + TD_REPORT_DATA_OFFSET
        + TD_REPORT_DATA_BYTES
    ] = bytes.fromhex(expected)
    return quote.hex()


def assert_forged_quote_rejected(quote_hex: str, *, output: Path) -> None:
    """Run the host-side negative and require dcap-qvl to reject the unsigned value."""

    output.write_text(quote_hex + "\n", encoding="utf-8")
    result = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(output)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode == 0:
        raise AttestationError("dcap-qvl accepted a locally hand-assembled quote")


def verify_quote(quote_path: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode != 0:
        raise AttestationError(
            f"dcap-qvl rejected quote {quote_path}: {result.stderr.strip()}"
        )
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AttestationError("dcap-qvl returned invalid JSON") from error
    if (
        verdict.get("status") != "UpToDate"
        or verdict.get("advisory_ids") != []
        or verdict.get("qe_status", {}).get("status") != "UpToDate"
        or verdict.get("platform_status", {}).get("status") != "UpToDate"
    ):
        raise AttestationError("quote TCB posture is not fully UpToDate")
    return result


def decode_quote(quote_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["dcap-qvl", "decode", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AttestationError(
            f"dcap-qvl could not decode quote: {result.stderr.strip()}"
        )
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AttestationError("dcap-qvl returned invalid decode JSON") from error
    header = decoded.get("header", {})
    if header.get("version") != 4 or header.get("tee_type") != 129:
        raise AttestationError("decoded quote is not TDX v4")
    if not isinstance(decoded.get("report", {}).get("TD10", {}).get("mr_td"), str):
        raise AttestationError("decoded quote has no TD10 mr_td")
    return decoded


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-data", required=True, help="hex report_data payload")
    parser.add_argument("--socket", type=Path, default=SOCKET_PATH)
    parser.add_argument("--quote-out", type=Path, required=True)
    parser.add_argument("--response-out", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--decode-out", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        response = request_quote(args.report_data, socket_path=args.socket)
        args.quote_out.write_text(response["quote"] + "\n", encoding="utf-8")
        args.response_out.write_text(
            json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if args.verify:
            verify_quote(args.quote_out)
        if args.decode_out is not None:
            decoded = decode_quote(args.quote_out)
            args.decode_out.write_text(
                json.dumps(decoded, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
    except AttestationError as error:
        print(json.dumps({"attestation": False, "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "attestation": True,
                "quote_hex_length": len(response["quote"]),
                "report_data": response["report_data"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
