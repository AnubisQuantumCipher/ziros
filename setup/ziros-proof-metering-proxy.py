#!/usr/bin/env python3
"""Minimal local metering proxy for the hosted proof lane."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def decode_segment(value: str) -> bytes:
    padding_needed = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding_needed))


def public_key_from_jwk(jwk: dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise ValueError("unsupported jwk type")
    n = int.from_bytes(decode_segment(jwk["n"]), "big")
    e = int.from_bytes(decode_segment(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


class AccessTokenValidator:
    def __init__(self, issuer: str, audiences: list[str], jwks_url: str, *, leeway_seconds: int = 60, cache_seconds: int = 900):
        self.issuer = issuer
        self.audiences = audiences
        self.jwks_url = jwks_url
        self.leeway_seconds = leeway_seconds
        self.cache_seconds = cache_seconds
        self._keys_by_kid: dict[str, rsa.RSAPublicKey] = {}
        self._fetched_at = 0.0

    def _refresh_keys(self) -> None:
        if self._keys_by_kid and (time.time() - self._fetched_at) < self.cache_seconds:
            return
        with urllib.request.urlopen(self.jwks_url, timeout=10) as response:
            payload = json.loads(response.read().decode())
        keys = {}
        for jwk in payload.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            keys[kid] = public_key_from_jwk(jwk)
        if not keys:
            raise ValueError("no jwks keys returned")
        self._keys_by_kid = keys
        self._fetched_at = time.time()

    def verify(self, token: str) -> dict[str, Any]:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
        except ValueError as error:
            raise ValueError("malformed_jwt") from error

        header = json.loads(decode_segment(header_b64))
        payload = json.loads(decode_segment(payload_b64))
        if header.get("alg") != "RS256":
            raise ValueError("unsupported_alg")
        kid = header.get("kid")
        if not kid:
            raise ValueError("missing_kid")

        self._refresh_keys()
        public_key = self._keys_by_kid.get(kid)
        if public_key is None:
            self._fetched_at = 0
            self._refresh_keys()
            public_key = self._keys_by_kid.get(kid)
        if public_key is None:
            raise ValueError("unknown_kid")

        signed = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = decode_segment(signature_b64)
        public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())

        now = int(time.time())
        leeway = self.leeway_seconds
        if payload.get("iss") != self.issuer:
            raise ValueError("invalid_issuer")
        aud = payload.get("aud") or []
        aud_list = aud if isinstance(aud, list) else [aud]
        if not any(value in aud_list for value in self.audiences):
            raise ValueError("invalid_audience")
        exp = int(payload.get("exp") or 0)
        if exp and (now - leeway) >= exp:
            raise ValueError("token_expired")
        nbf = int(payload.get("nbf") or 0)
        if nbf and (now + leeway) < nbf:
            raise ValueError("token_not_yet_valid")
        iat = int(payload.get("iat") or 0)
        if iat and (now + leeway) < iat:
            raise ValueError("token_issued_in_future")
        return payload


class MeteringProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ZirOSProofMeteringProxy/1.0"

    @property
    def proxy(self) -> "MeteringProxyServer":
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
        start = time.perf_counter()
        config = self.proxy.load_config()
        route = urllib.parse.urlparse(self.path).path or "/"
        remote = self.client_address[0]

        if remote not in {"127.0.0.1", "::1"}:
            self._reject(HTTPStatus.FORBIDDEN, "non_local_client", route=route, latency_ms=0.0)
            return

        token = self.headers.get("Cf-Access-Jwt-Assertion") or self.headers.get("cf-access-jwt-assertion")
        if not token:
            self._reject(HTTPStatus.UNAUTHORIZED, "missing_cf_access_jwt_assertion", route=route, latency_ms=0.0)
            return

        try:
            claims = self.proxy.validator.verify(token)
        except Exception as error:  # pragma: no cover - runtime guard
            self._reject(HTTPStatus.UNAUTHORIZED, f"invalid_access_jwt:{error}", route=route, latency_ms=(time.perf_counter() - start) * 1000)
            return

        service_token_client_id = str(claims.get("common_name") or claims.get("service_token_id") or "")
        customer_id = self.proxy.customer_id_for(service_token_client_id)
        request_body = self._read_request_body()
        upstream_url = self._upstream_url(config["upstream"])

        request = urllib.request.Request(upstream_url, data=request_body, method=self.command)
        for header, value in self.headers.items():
            key = header.lower()
            if key in HOP_BY_HOP_HEADERS or key in {
                "authorization",
                "host",
                "content-length",
                "cf-access-jwt-assertion",
                "cf-access-client-id",
                "cf-access-client-secret",
                "cookie",
            }:
                continue
            request.add_header(header, value)
        request.add_header("X-ZirOS-Customer", customer_id)
        request.add_header("X-ZirOS-Service-Token-Client-Id", service_token_client_id)
        request.add_header("X-Forwarded-Host", self.headers.get("Host", ""))
        request.add_header("X-Forwarded-Proto", "https")

        try:
            with urllib.request.urlopen(request, timeout=float(config.get("upstream_timeout_seconds", 30))) as response:
                body = response.read()
                self.send_response(response.status)
                self._write_common_headers(content_length=len(body))
                self.send_header("X-ZirOS-Customer", customer_id)
                for header, value in response.getheaders():
                    key = header.lower()
                    if key in HOP_BY_HOP_HEADERS or key == "content-length":
                        continue
                    self.send_header(header, value)
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self._log_request(
                    route=route,
                    status_code=response.status,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    customer_id=customer_id,
                    service_token_client_id=service_token_client_id,
                    upstream_error=False,
                )
        except urllib.error.HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self._write_common_headers(content_length=len(body))
            self.send_header("Content-Type", error.headers.get_content_type())
            self.send_header("X-ZirOS-Customer", customer_id)
            self.end_headers()
            if body:
                self.wfile.write(body)
            self._log_request(
                route=route,
                status_code=error.code,
                latency_ms=(time.perf_counter() - start) * 1000,
                customer_id=customer_id,
                service_token_client_id=service_token_client_id,
                upstream_error=True,
            )
        except Exception as error:  # pragma: no cover - runtime guard
            payload = json.dumps({"error": "bad_gateway", "detail": str(error)}).encode("utf-8")
            self.send_response(HTTPStatus.BAD_GATEWAY)
            self._write_common_headers(content_length=len(payload))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
            self._log_request(
                route=route,
                status_code=int(HTTPStatus.BAD_GATEWAY),
                latency_ms=(time.perf_counter() - start) * 1000,
                customer_id=customer_id,
                service_token_client_id=service_token_client_id,
                upstream_error=True,
            )

    def _read_request_body(self) -> bytes | None:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            return None
        size = int(content_length)
        if size <= 0:
            return None
        return self.rfile.read(size)

    def _upstream_url(self, base_url: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        path_parts = urllib.parse.urlsplit(path)
        return urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                path_parts.path,
                path_parts.query,
                "",
            )
        )

    def _write_common_headers(self, *, content_length: int) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Cf-Access-Jwt-Assertion")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(content_length))

    def _reject(self, status: HTTPStatus, reason: str, *, route: str, latency_ms: float) -> None:
        payload = json.dumps({"error": "forbidden", "reason": reason}).encode("utf-8")
        self.send_response(status)
        self._write_common_headers(content_length=len(payload))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)
        self._log_reject(route=route, status_code=int(status), latency_ms=latency_ms, reason=reason)

    def _log_request(self, *, route: str, status_code: int, latency_ms: float, customer_id: str, service_token_client_id: str, upstream_error: bool) -> None:
        sys.stdout.write(
            json.dumps(
                {
                    "schema": "ziros-metering-request-v1",
                    "ts": utc_now_iso(),
                    "method": self.command,
                    "route": route,
                    "status_code": status_code,
                    "latency_ms": round(latency_ms, 2),
                    "customer_id": customer_id,
                    "service_token_client_id": service_token_client_id,
                    "upstream_error": upstream_error,
                }
            )
            + "\n"
        )
        sys.stdout.flush()

    def _log_reject(self, *, route: str, status_code: int, latency_ms: float, reason: str) -> None:
        sys.stdout.write(
            json.dumps(
                {
                    "schema": "ziros-metering-reject-v1",
                    "ts": utc_now_iso(),
                    "method": self.command,
                    "route": route,
                    "status_code": status_code,
                    "latency_ms": round(latency_ms, 2),
                    "reason": reason,
                }
            )
            + "\n"
        )
        sys.stdout.flush()


class MeteringProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], config_path: Path):
        super().__init__(address, handler)
        self.config_path = config_path
        self._config_cache: dict[str, Any] | None = None
        self._config_mtime: float | None = None
        self._customer_map: dict[str, str] = {}
        self._customer_map_mtime: float | None = None
        config = self.load_config()
        self.validator = AccessTokenValidator(
            issuer=config["issuer"],
            audiences=config["audiences"],
            jwks_url=config["jwks_url"],
            leeway_seconds=int(config.get("leeway_seconds", 60)),
            cache_seconds=int(config.get("jwks_cache_seconds", 900)),
        )

    def load_config(self) -> dict[str, Any]:
        stat = self.config_path.stat()
        if self._config_cache is not None and self._config_mtime == stat.st_mtime:
            return self._config_cache
        raw = json.loads(self.config_path.read_text())
        required = ("bind_host", "bind_port", "upstream", "issuer", "audiences", "jwks_url", "customer_map_path")
        for field in required:
            if field not in raw:
                raise RuntimeError(f"missing config field: {field}")
        self._config_cache = raw
        self._config_mtime = stat.st_mtime
        return raw

    def customer_id_for(self, service_token_client_id: str) -> str:
        config = self.load_config()
        path = Path(str(config["customer_map_path"]).replace("~", str(Path.home())))
        if path.exists():
            stat = path.stat()
            if self._customer_map_mtime != stat.st_mtime:
                payload = read_json(path, {"customers": []})
                mapping = {}
                for entry in payload.get("customers", []):
                    client_id = entry.get("access_client_id")
                    if isinstance(client_id, str) and client_id:
                        mapping[client_id] = entry["customer_id"]
                self._customer_map = mapping
                self._customer_map_mtime = stat.st_mtime
        return self._customer_map.get(service_token_client_id, "unknown")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hosted proof metering proxy")
    parser.add_argument(
        "--config",
        default=str(Path.home() / ".jacobian" / "hosted-proof-lane" / "metering-proxy.json"),
        help="Path to the proxy configuration JSON file.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser()
    config = read_json(config_path, None)
    if not isinstance(config, dict):
        print(f"ERROR: missing config file: {config_path}", file=sys.stderr)
        return 1
    server = MeteringProxyServer((str(config["bind_host"]), int(config["bind_port"])), MeteringProxyHandler, config_path)
    sys.stdout.write(
        json.dumps(
            {
                "schema": "ziros-metering-proxy-start-v1",
                "ts": utc_now_iso(),
                "bind_host": config["bind_host"],
                "bind_port": config["bind_port"],
                "upstream": config["upstream"],
            }
        )
        + "\n"
    )
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
