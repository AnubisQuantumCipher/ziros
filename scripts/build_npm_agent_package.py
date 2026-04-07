#!/usr/bin/env python3
import json
import pathlib
import re


def workspace_version(root: pathlib.Path) -> str:
    cargo_toml = (root / "Cargo.toml").read_text()
    match = re.search(r'\[workspace\.package\][\s\S]*?version = "([^"]+)"', cargo_toml)
    if not match:
        raise SystemExit("could not find workspace version in Cargo.toml")
    return match.group(1)


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    package_path = root / "packaging" / "npm" / "agent" / "package.json"
    package = json.loads(package_path.read_text())
    package["version"] = workspace_version(root)
    package_path.write_text(json.dumps(package, indent=2) + "\n")
    print(package_path)


if __name__ == "__main__":
    main()
