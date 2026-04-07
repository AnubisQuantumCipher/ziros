#!/usr/bin/env python3
"""Minimal authenticated reverse proxy for the hosted Midnight proof-server lane."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ConfigError(RuntimeError):
    pass


class EntitlementProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ZirOSProofAccessProxy/1.0"

    @property
    def proxy(self) -> "EntitlementProxyServer":
        return self.server  # type: ignore[return-value]

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._write_common_headers(content_length=0)
        self.end_headers()

    def do_GET(self) -> None:
        self._proxy_request()

    def do_POST(self) -> None:
        self._proxy_request()

    def do_PUT(self) -> None:
        self._proxy_request()

    def do_PATCH(self) -> None:
        self._proxy_request()

    def do_DELETE(self) -> None:
        self._proxy_request()

    def log_message(self, format: str, *args: Any) -> None:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sys.stdout.write(f"{timestamp} {self.address_string()} {format % args}\n")
        sys.stdout.flush()

    def _proxy_request(self) -> None:
        config = self.proxy.load_config()
        entitlement, reject_reason = self._authorize(config)
        if entitlement is None:
            self._reject(HTTPStatus.UNAUTHORIZED, reject_reason or "unauthorized")
            return

        try:
            upstream_url = self._upstream_url(config["upstream"])
            request_body = self._read_request_body()
            request = urllib.request.Request(
                upstream_url,
                data=request_body,
                method=self.command,
            )

            for header, value in self.headers.items():
                key = header.lower()
                if key in HOP_BY_HOP_HEADERS or key in {"authorization", "host", "content-length"}:
                    continue
                request.add_header(header, value)

            request.add_header("X-ZirOS-Customer", entitlement["id"])
            request.add_header("X-Forwarded-Host", self.headers.get("Host", ""))
            request.add_header("X-Forwarded-Proto", "https")

            timeout = float(config.get("upstream_timeout_seconds", 30))
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
                self.send_response(response.status)
                self._write_common_headers(content_length=len(body))
                self.send_header("X-ZirOS-Customer", entitlement["id"])
                for header, value in response.getheaders():
                    key = header.lower()
                    if key in HOP_BY_HOP_HEADERS or key == "content-length":
                        continue
                    self.send_header(header, value)
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self.log_message(
                    '"%s %s" %s customer=%s',
                    self.command,
                    self.path,
                    response.status,
                    entitlement["id"],
                )
        except urllib.error.HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self._write_common_headers(content_length=len(body))
            self.send_header("Content-Type", error.headers.get_content_type())
            self.send_header("X-ZirOS-Customer", entitlement["id"])
            for header, value in error.headers.items():
                key = header.lower()
                if key in HOP_BY_HOP_HEADERS or key in {"content-length", "content-type"}:
                    continue
                self.send_header(header, value)
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.log_message(
                '"%s %s" %s customer=%s upstream_error',
                self.command,
                self.path,
                error.code,
                entitlement["id"],
            )
        except Exception as error:  # pragma: no cover - runtime guard
            payload = json.dumps(
                {
                    "error": "bad_gateway",
                    "detail": str(error),
                }
            ).encode("utf-8")
            self.send_response(HTTPStatus.BAD_GATEWAY)
            self._write_common_headers(content_length=len(payload))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            self.log_message(
                '"%s %s" %s customer=%s detail=%s',
                self.command,
                self.path,
                HTTPStatus.BAD_GATEWAY,
                entitlement["id"],
                str(error),
            )

    def _reject(self, status: HTTPStatus, reason: str) -> None:
        payload = json.dumps({"error": "unauthorized", "reason": reason}).encode("utf-8")
        self.send_response(status)
        self._write_common_headers(content_length=len(payload))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)
        self.log_message('"%s %s" %s reason=%s', self.command, self.path, status, reason)

    def _write_common_headers(self, *, content_length: int) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(content_length))

    def _read_request_body(self) -> bytes | None:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            return None
        size = int(content_length)
        if size <= 0:
            return None
        return self.rfile.read(size)

    def _authorize(self, config: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return None, "missing_bearer_token"
        token = authorization[len("Bearer ") :].strip()
        if not token:
            return None, "empty_bearer_token"
        digest = sha256_hex(token)
        for entitlement in config["allowlist"]:
            if entitlement.get("status") != "active":
                continue
            expected = entitlement.get("sha256")
            if isinstance(expected, str) and hmac.compare_digest(expected, digest):
                return entitlement, None
        return None, "invalid_or_revoked_token"

    def _upstream_url(self, base_url: str) -> str:
        if self.path.startswith("http://") or self.path.startswith("https://"):
            return self.path
        parsed = urllib.parse.urlparse(base_url)
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                path,
                "",
                "",
                "",
            )
        )


class EntitlementProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], config_path: Path):
        super().__init__(address, handler)
        self.config_path = config_path

    def load_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text())
        except FileNotFoundError as error:
            raise ConfigError(f"config not found: {self.config_path}") from error
        except json.JSONDecodeError as error:
            raise ConfigError(f"invalid config JSON: {error}") from error

        allowlist = raw.get("allowlist")
        if not isinstance(allowlist, list):
            raise ConfigError("config allowlist must be an array")
        upstream = raw.get("upstream")
        if not isinstance(upstream, str) or not upstream.startswith("http"):
            raise ConfigError("config upstream must be an http(s) URL")
        raw.setdefault("upstream_timeout_seconds", 30)
        return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authenticated reverse proxy for the hosted Midnight proof-server.")
    parser.add_argument(
        "--config",
        default=str(Path.home() / ".jacobian" / "hosted-proof-lane" / "entitlements.json"),
        help="Path to the entitlement config JSON file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser()
    bootstrap = json.loads(config_path.read_text())
    bind_host = bootstrap.get("bind_host", "127.0.0.1")
    bind_port = int(bootstrap.get("bind_port", 6310))
    server = EntitlementProxyServer((bind_host, bind_port), EntitlementProxyHandler, config_path)
    print(
        f"Hosted proof access proxy listening on http://{bind_host}:{bind_port} -> {bootstrap.get('upstream')}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - local operator shutdown
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
