#!/usr/bin/env python3
import os
import sys


def main() -> int:
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: normalize_fstar_depend.py <src> <dst> <real_root> <logical_root>"
        )

    src, dst, real_root, logical_root = sys.argv[1:]

    with open(src, "r", encoding="utf-8") as infile:
        text = infile.read()

    for old in (
        real_root,
        real_root.replace(" ", "\\ "),
        real_root.replace(" ", "/\\ "),
    ):
        text = text.replace(old, logical_root)

    with open(dst, "w", encoding="utf-8") as outfile:
        outfile.write(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
