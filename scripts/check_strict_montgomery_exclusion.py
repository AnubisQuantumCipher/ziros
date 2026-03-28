#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
STRICT_CRATE_SOURCES = {
    "zkf-core": REPO_ROOT / "zkf-core" / "src",
    "zkf-backends": REPO_ROOT / "zkf-backends" / "src",
    "zkf-runtime": REPO_ROOT / "zkf-runtime" / "src",
}

DISALLOWED_PATTERNS = (
    (
        "direct zkf-crypto-accel montgomery import",
        re.compile(r"zkf_crypto_accel\s*::\s*montgomery", re.MULTILINE),
    ),
    (
        "grouped zkf-crypto-accel montgomery import",
        re.compile(
            r"use\s+zkf_crypto_accel\s*::\s*\{[^}]*\bmontgomery\b",
            re.MULTILINE | re.DOTALL,
        ),
    ),
    (
        "direct BN254 accelerator call",
        re.compile(r"\b(?:mont_mul_bn254|batch_mont_mul_bn254)\b", re.MULTILINE),
    ),
)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def main() -> None:
    violations: list[str] = []

    for crate_name, src_dir in STRICT_CRATE_SOURCES.items():
        if not src_dir.is_dir():
            raise SystemExit(f"missing strict crate source directory: {src_dir}")

        for path in sorted(src_dir.rglob("*.rs")):
            text = path.read_text(encoding="utf-8")
            for description, pattern in DISALLOWED_PATTERNS:
                match = pattern.search(text)
                if match is None:
                    continue
                rel_path = path.relative_to(REPO_ROOT)
                violations.append(
                    f"{rel_path}:{line_number(text, match.start())}: {description}"
                )

    if violations:
        joined = "\n".join(violations)
        raise SystemExit(
            "strict proof lanes must fail closed on zkf-crypto-accel Montgomery routing; "
            "remove these imports or calls:\n"
            f"{joined}"
        )


if __name__ == "__main__":
    main()
