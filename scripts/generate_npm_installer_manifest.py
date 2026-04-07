#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone


def workspace_version(root: pathlib.Path) -> str:
    cargo_toml = (root / "Cargo.toml").read_text()
    match = re.search(r'\[workspace\.package\][\s\S]*?version = "([^"]+)"', cargo_toml)
    if not match:
        raise SystemExit("could not find workspace version in Cargo.toml")
    return match.group(1)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[1]))
    parser.add_argument("--archive")
    parser.add_argument("--archive-url")
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--out")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    version = workspace_version(root)
    out_path = pathlib.Path(args.out) if args.out else root / "release" / "npm" / "installer-manifest.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    archive_url = args.archive_url or (
        f"https://github.com/anubisquantumcipher/ziros/releases/download/v{version}/"
        f"ziros-darwin-arm64-v{version}.tar.gz"
    )
    sha256 = "PENDING"
    if args.archive:
        sha256 = sha256_file(pathlib.Path(args.archive).resolve())

    payload = {
        "schema": "ziros-installer-manifest-v1",
        "version": version,
        "release_tag": f"v{version}",
        "channel": args.channel,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platforms": [
            {
                "platform": "darwin-arm64",
                "archive_url": archive_url,
                "sha256": sha256,
                "binaries": ["ziros", "zkf", "ziros-agentd"],
            }
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    main()
