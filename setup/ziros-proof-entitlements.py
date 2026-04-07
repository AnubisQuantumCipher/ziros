#!/usr/bin/env python3
"""Issue, list, and revoke credentials for the hosted Midnight proof-server lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def default_state_path() -> Path:
    return Path.home() / ".jacobian" / "hosted-proof-lane" / "entitlements.json"


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        return {
            "schema": "ziros-hosted-proof-entitlements-v1",
            "bind_host": "127.0.0.1",
            "bind_port": 6310,
            "upstream": "http://127.0.0.1:6300",
            "upstream_timeout_seconds": 30,
            "allowlist": [],
        }
    return json.loads(path.read_text())


def store_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2) + "\n")


def issue(args: argparse.Namespace) -> int:
    path = Path(args.state).expanduser()
    state = load_state(path)
    allowlist = state.setdefault("allowlist", [])
    token = args.token or secrets.token_urlsafe(32)

    existing = next((entry for entry in allowlist if entry.get("id") == args.customer_id), None)
    if existing is not None and existing.get("status") == "active" and not args.rotate:
        raise SystemExit(f"customer {args.customer_id} already has an active entitlement; use --rotate to replace it")

    entitlement = {
        "id": args.customer_id,
        "display_name": args.display_name or args.customer_id,
        "status": "active",
        "issued_at": now_utc(),
        "issued_by": "codex",
        "notes": args.note or "",
        "sha256": sha256_hex(token),
    }

    if existing is None:
        allowlist.append(entitlement)
    else:
        existing.clear()
        existing.update(entitlement)

    store_state(path, state)

    token_path = Path(args.token_out).expanduser() if args.token_out else path.parent / f"{args.customer_id}.token"
    token_path.write_text(token + "\n")
    token_path.chmod(0o600)

    print(
        json.dumps(
            {
                "customer_id": args.customer_id,
                "display_name": entitlement["display_name"],
                "status": entitlement["status"],
                "token_path": str(token_path),
                "state_path": str(path),
            },
            indent=2,
        )
    )
    return 0


def revoke(args: argparse.Namespace) -> int:
    path = Path(args.state).expanduser()
    state = load_state(path)
    allowlist = state.setdefault("allowlist", [])
    existing = next((entry for entry in allowlist if entry.get("id") == args.customer_id), None)
    if existing is None:
        raise SystemExit(f"customer {args.customer_id} not found")

    existing["status"] = "revoked"
    existing["revoked_at"] = now_utc()
    existing["revoked_reason"] = args.reason or "manual revoke"
    store_state(path, state)
    print(
        json.dumps(
            {
                "customer_id": args.customer_id,
                "status": existing["status"],
                "state_path": str(path),
            },
            indent=2,
        )
    )
    return 0


def list_customers(args: argparse.Namespace) -> int:
    path = Path(args.state).expanduser()
    state = load_state(path)
    allowlist = state.setdefault("allowlist", [])
    print(json.dumps({"state_path": str(path), "allowlist": allowlist}, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage hosted proof-server entitlements.")
    parser.add_argument("--state", default=str(default_state_path()), help="Path to entitlement state JSON.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue_parser = subparsers.add_parser("issue", help="Issue or rotate a customer credential.")
    issue_parser.add_argument("customer_id", help="Stable customer identifier.")
    issue_parser.add_argument("--display-name", help="Human-readable customer name.")
    issue_parser.add_argument("--note", help="Operator note attached to this entitlement.")
    issue_parser.add_argument("--token", help="Use a specific bearer token instead of generating one.")
    issue_parser.add_argument("--token-out", help="Where to write the generated token.")
    issue_parser.add_argument("--rotate", action="store_true", help="Replace an existing active credential.")
    issue_parser.set_defaults(func=issue)

    revoke_parser = subparsers.add_parser("revoke", help="Revoke a customer credential.")
    revoke_parser.add_argument("customer_id", help="Stable customer identifier.")
    revoke_parser.add_argument("--reason", help="Why this entitlement was revoked.")
    revoke_parser.set_defaults(func=revoke)

    list_parser = subparsers.add_parser("list", help="Show the current allowlist.")
    list_parser.set_defaults(func=list_customers)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
