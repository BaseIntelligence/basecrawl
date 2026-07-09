import json
import subprocess
from pathlib import Path

import basecrawl


ROOT = Path(__file__).resolve().parents[3]
URL = "https://example.com"
FORMATS = ["rawHtml"]


def cli_proof() -> dict[str, object]:
    output = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(ROOT / "Cargo.toml"),
            "--package",
            "basecrawl-core",
            "--bin",
            "basecrawl",
            "--",
            URL,
            "--formats",
            ",".join(FORMATS),
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(output.stdout)


def test_scrape_returns_the_cli_scrapeproof_shape() -> None:
    proof = basecrawl.scrape(URL, formats=FORMATS, render_enabled=False)
    expected = cli_proof()

    assert isinstance(proof, dict)
    assert list(proof) == list(expected)
    assert proof["request"]["formats"] == expected["request"]["formats"]
    assert proof["attestation"]["quote"] is None
    assert proof["sdk_signature"]["sig"] is None
