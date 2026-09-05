"""Sentry API HTTP server.

Uses ThreadingHTTPServer for concurrent request handling.
Routes all requests through auth middleware, serves static files
for the dashboard frontend, and dispatches API routes.

Usage:
    python -m sentry serve          # Start API server
    python -m sentry replay --serve # Start with replay demo data
"""

from __future__ import annotations

import logging
import os
import sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any
from urllib.parse import urlparse, parse_qs

from sentry.api.auth import Authenticator
from sentry.api.routes import (
    _parse_cookies,
    _html_response,
    _json_response,
    _redirect,
    make_login_handler,
    make_logout_handler,
    make_status_handler,
    make_threats_handler,
    make_mitigations_handler,
    make_revoke_handler,
    make_topology_handler,
    make_replay_handler,
)

logger = logging.getLogger(__name__)

# Paths that don't require authentication
PUBLIC_PATHS = {"/login.html", "/api/v1/login", "/healthz"}


class SentryHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Sentry API and dashboard."""

    authenticator: Authenticator
    static_dir: str
    routes: dict[str, Any]
    executor: Any | None

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._handle_request("GET")

    def do_POST(self) -> None:
        """Handle POST requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self._handle_request("POST", body)

    def _handle_request(self, method: str, body: bytes = b"") -> None:
        """Route and handle an HTTP request."""
        parsed = urlparse(self.path)
        path = parsed.path
        client_ip = self.client_address[0]

        # Health check (no auth)
        if path == "/healthz":
            self._send_response(200, {"Content-Type": "text/plain"}, b"ok")
            return

        # Static files — check public paths
        if path in PUBLIC_PATHS or path.startswith("/api/v1/login"):
            pass  # Skip auth check
        elif path.startswith("/api/v1/"):
            # API route — check auth
            headers = {k: v for k, v in self.headers.items()}
            cookie_header = headers.get("Cookie", "")
            cookies = _parse_cookies(cookie_header)
            if not self.authenticator.check_request(headers, cookies):
                self._send_response(401, {"Content-Type": "application/json"},
                                    b'{"error":"Unauthorized"}')
                return
        elif not path.startswith("/api/"):
            # Static file — check auth via cookie
            headers = {k: v for k, v in self.headers.items()}
            cookie_header = headers.get("Cookie", "")
            cookies = _parse_cookies(cookie_header)
            if not self.authenticator.check_request(headers, cookies):
                # Redirect to login
                self._send_response(302, {"Location": "/login.html"}, b"")
                return

        # Route API requests
        if path.startswith("/api/v1/"):
            self._handle_api(method, path, body, client_ip)
            return

        # Serve static files
        self._serve_static(path)

    def _handle_api(
        self, method: str, path: str, body: bytes, client_ip: str
    ) -> None:
        """Dispatch API route to handler."""
        # Match routes
        if path == "/api/v1/login" and method == "POST":
            handler = make_login_handler(self.authenticator)
        elif path == "/api/v1/logout" and method == "POST":
            handler = make_logout_handler(self.authenticator)
        elif path == "/api/v1/status":
            handler = make_status_handler()
        elif path == "/api/v1/threats":
            handler = make_threats_handler()
        elif path == "/api/v1/mitigations" and method == "GET":
            handler = make_mitigations_handler(self.executor)
        elif path.startswith("/api/v1/mitigations/") and path.endswith("/revoke"):
            handler = make_revoke_handler(self.executor)
        elif path == "/api/v1/topology":
            handler = make_topology_handler()
        elif path.startswith("/api/v1/replay"):
            handler = make_replay_handler()
        else:
            self._send_response(404, {"Content-Type": "application/json"},
                                b'{"error":"Not found"}')
            return

        headers_dict = {k: v for k, v in self.headers.items()}
        status, resp_headers, resp_body = handler(
            method, path, headers_dict, body, client_ip
        )
        self._send_response(status, resp_headers, resp_body)

    def _serve_static(self, path: str) -> None:
        """Serve a static file from the static directory."""
        # Default to index
        if path == "/":
            path = "/login.html"

        # Sanitize path
        file_path = os.path.join(self.static_dir, path.lstrip("/"))
        file_path = os.path.normpath(file_path)

        # Ensure path is within static_dir
        if not file_path.startswith(os.path.normpath(self.static_dir)):
            self._send_response(403, {"Content-Type": "text/plain"},
                                b"Forbidden")
            return

        if not os.path.isfile(file_path):
            self._send_response(404, {"Content-Type": "text/plain"},
                                b"Not found")
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except OSError:
            self._send_response(500, {"Content-Type": "text/plain"},
                                b"Internal error")
            return

        # Determine content type
        ext = os.path.splitext(file_path)[1].lower()
        content_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json",
            ".png": "image/png",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }
        ct = content_types.get(ext, "application/octet-stream")

        self._send_response(200, {"Content-Type": ct}, content)

    def _send_response(
        self, status: int, headers: dict[str, str], body: bytes
    ) -> None:
        """Send an HTTP response."""
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Override to use structured logging."""
        logger.debug(
            "HTTP request",
            extra={
                "client": self.client_address[0],
                "method": getattr(self, "command", "?"),
                "path": getattr(self, "path", "?"),
                "status": args[0] if args else "?",
            },
        )


def create_server(
    host: str = "0.0.0.0",
    port: int = 9090,
    authenticator: Authenticator | None = None,
    executor: Any = None,
    static_dir: str | None = None,
) -> ThreadingHTTPServer:
    """Create and configure the Sentry HTTP server.

    Args:
        host: Bind address
        port: Bind port
        authenticator: Authentication manager
        executor: Mitigation executor (optional, for /api/v1/mitigations)
        static_dir: Path to static files directory

    Returns:
        Configured ThreadingHTTPServer
    """
    if static_dir is None:
        static_dir = os.path.join(
            os.path.dirname(__file__), "static"
        )

    if authenticator is None:
        from sentry.core.config import ApiConfig
        cfg = ApiConfig()
        authenticator = Authenticator(
            valid_token=cfg.auth_token,
            session_ttl_seconds=cfg.session_ttl_seconds,
            max_attempts=cfg.rate_limit_max_attempts,
            lockout_seconds=cfg.rate_limit_lockout_seconds,
        )

    # Create server with handler configuration via class attributes
    handler = type(
        "ConfiguredHandler",
        (SentryHTTPHandler,),
        {
            "authenticator": authenticator,
            "static_dir": static_dir,
            "executor": executor,
        },
    )

    server = ThreadingHTTPServer((host, port), handler)
    logger.info(
        f"Sentry API server listening on {host}:{port}",
        extra={"static_dir": static_dir},
    )
    return server
