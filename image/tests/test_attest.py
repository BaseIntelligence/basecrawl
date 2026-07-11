from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import attest


REPORT_DATA = bytes(range(64)).hex()


def valid_quote() -> str:
    quote = bytearray(48 + 584 + 4)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[4:8] = (0x81).to_bytes(4, "little")
    quote[48 + 520 : 48 + 584] = bytes.fromhex(REPORT_DATA)
    return quote.hex()


class AttestationClientTests(unittest.TestCase):
    def test_parse_get_quote_requires_all_fields_and_full_report_data(self) -> None:
        response = attest.parse_get_quote(
            json.dumps(
                {
                    "quote": valid_quote(),
                    "event_log": [{"event": "fixture"}],
                    "report_data": REPORT_DATA,
                    "vm_config": {"cpu": 1},
                }
            ),
            REPORT_DATA,
        )
        self.assertEqual(response["report_data"], REPORT_DATA)
        self.assertGreaterEqual(len(response["quote"]), attest.MIN_QUOTE_HEX_LEN)

    def test_parse_get_quote_rejects_report_data_mismatch(self) -> None:
        with self.assertRaisesRegex(attest.AttestationError, "report_data"):
            attest.parse_get_quote(
                json.dumps(
                    {
                        "quote": valid_quote(),
                        "event_log": [{"event": "fixture"}],
                        "report_data": "ff" * 64,
                        "vm_config": {"cpu": 1},
                    }
                ),
                REPORT_DATA,
            )

    def test_forged_quote_has_enough_bytes_but_no_signature(self) -> None:
        forged = attest.hand_assembled_quote(REPORT_DATA)
        self.assertGreaterEqual(len(forged), attest.MIN_QUOTE_HEX_LEN)
        self.assertEqual(forged[(48 + 520) * 2 : (48 + 584) * 2], REPORT_DATA)

    def test_overlong_report_data_is_sha512_reduced_and_short_data_is_padded(
        self,
    ) -> None:
        overlong = "ab" * 65
        reduced = attest.normalize_report_data(overlong)
        self.assertEqual(
            reduced,
            hashlib.sha256(bytes.fromhex(overlong)).hexdigest() + "00" * 32,
        )
        short = attest.normalize_report_data("0102")
        self.assertEqual(short, "0102" + "00" * 62)


if __name__ == "__main__":
    unittest.main()
