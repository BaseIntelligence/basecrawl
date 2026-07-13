"""Claims-honesty docs gates for basecrawl (VAL-HARDEN-004 / VAL-HARDEN-023).

Pure markdown/source greps — no live CVM. Confirms security docs document the
TEE.fail residual + managed-cloud mitigation and that absolute trust / absolute
TEE language is absent from first-party docs.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_DOCS = _REPO / "docs"

_ABSOLUTE_TRUST_RE = re.compile(
    r"(?i)\b(?:trustless|100%|guaranteed authenticity|guaranteed|fully\s+trust|"
    r"zero\s+trust\s+required)\b"
)
_ABSOLUTE_TEE_RE = re.compile(
    r"(?i)\b(?:unconditional|tamper[-\s]?proof|unbreakable|physically\s+secure|"
    r"impossible\s+to\s+forge)\b"
)

_DENIAL = re.compile(
    r"(?i)(?:"
    r"never|no\s+string|must\s+never|must\s+not|do\s+not|does\s+not|forbidden|"
    r"free\s+of|without|not\b|non[-\s]?goal|honest|honesty|deny|avoid|reject|"
    r"do\s+not\s+write|never\s+write|no\s+claim|not\s+an\s+absolute|"
    r"never\s+an\s+absolute|rather\s+than|cryptographically-anchored"
    r")"
)


def _is_meta(line: str) -> bool:
    if _DENIAL.search(line):
        return True
    if re.search(
        r"(?i)(?:never|not|no|without|forbid|forbidden|disallow|reject|avoid|"
        r"must\s+not|do\s+not|does\s+not|may\s+not|cannot|free\s+of)",
        line,
    ):
        return True
    lowered = line.lower()
    for marker in (
        "forbidden",
        "honesty",
        "claim of",
        "claims of",
        "string claim",
        "physical security",
        "not physically compromised",
        "host not physically",
        "trust the host",
        "trusting the host",
        "physical tampering",
        "val-harden",
        "degrade",
        "absolute-trust",
        "absolute-tee",
        "absolute trust",
        "absolute tee",
    ):
        if marker in lowered:
            return True
    bare = lowered.strip(" \t,'\"[]():")
    if bare in {
        "trustless",
        "100%",
        "guarantee",
        "guaranteed",
        "unconditional",
        "tamper-proof",
        "unbreakable",
        "physically secure",
        "impossible to forge",
    }:
        return True
    if bare.startswith('"') and bare.endswith((",", '."', '".', '"')):
        return True
    return False


def _offenders(path: Path, pattern: re.Pattern[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    out: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not pattern.search(line):
            continue
        if _is_meta(line):
            continue
        out.append(f"{path.name}:{lineno}:{line.strip()}")
    return out


class ClaimsHonestyDocsTests(unittest.TestCase):
    def test_security_doc_exists_with_tee_fail_residual(self) -> None:
        security = _DOCS / "SECURITY.md"
        self.assertTrue(security.is_file(), "docs/SECURITY.md required")
        text = security.read_text(encoding="utf-8").lower()
        self.assertIn("tee.fail", text)
        self.assertIn("ddr5", text)
        self.assertIn("interposer", text)
        self.assertTrue("forge quotes" in text or "forge quote" in text)
        self.assertIn("read enclave memory", text)
        self.assertIn("no vendor fix", text)
        self.assertTrue("managed-cloud" in text or "managed cloud" in text)
        self.assertIn("cryptographically-anchored trust-but-audit", text)

    def test_trust_model_doc_names_honest_phrase(self) -> None:
        trust = _DOCS / "TRUST_MODEL.md"
        self.assertTrue(trust.is_file())
        text = trust.read_text(encoding="utf-8")
        self.assertIn("cryptographically-anchored trust-but-audit", text)

    def test_docs_free_of_absolute_trust_claims(self) -> None:
        offenders: list[str] = []
        for path in sorted(_DOCS.glob("*.md")):
            offenders.extend(_offenders(path, _ABSOLUTE_TRUST_RE))
        self.assertEqual(offenders, [], "absolute trust claims:\n" + "\n".join(offenders))

    def test_docs_free_of_absolute_tee_claims(self) -> None:
        offenders: list[str] = []
        for path in sorted(_DOCS.glob("*.md")):
            offenders.extend(_offenders(path, _ABSOLUTE_TEE_RE))
        self.assertEqual(offenders, [], "absolute TEE claims:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
