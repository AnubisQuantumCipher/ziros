#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require LCOV function coverage for selected Solidity entrypoints."
    )
    parser.add_argument("--lcov", required=True, help="path to lcov.info")
    parser.add_argument(
        "--function",
        action="append",
        required=True,
        dest="functions",
        help="function name that must have nonzero coverage",
    )
    args = parser.parse_args()

    lcov_path = Path(args.lcov)
    text = lcov_path.read_text()
    fn_counts: dict[str, int] = {}
    for line in text.splitlines():
        if line.startswith("FNDA:"):
            payload = line.removeprefix("FNDA:")
            count_str, name = payload.split(",", 1)
            fn_counts[name] = fn_counts.get(name, 0) + int(float(count_str))

    def coverage_for(function_name: str) -> int:
        total = fn_counts.get(function_name, 0)
        suffix = f".{function_name}"
        total += sum(
            count for name, count in fn_counts.items() if name.endswith(suffix)
        )
        return total

    missing = [name for name in args.functions if coverage_for(name) <= 0]
    if missing:
        raise SystemExit(
            f"missing nonzero LCOV function coverage for verifier entrypoints: {', '.join(missing)}"
        )
    print(
        "verified LCOV function coverage:",
        ", ".join(f"{name}={coverage_for(name)}" for name in args.functions),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
