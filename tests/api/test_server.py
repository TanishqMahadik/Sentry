"""Tests for sentry.api.server — HTTP server routing and auth middleware."""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest


def _get_free_port() -> int:
    """Find a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_request(
    port: int,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    cookie: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Make an HTTP request and return (status, headers, body)."""
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    if headers is None:
        headers = {}
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    status = resp.status
    resp_headers = dict(resp.getheaders())
    resp_body = resp.read()
    conn.close()
    return status, resp_headers, resp_body


class TestServerRouting(unittest.TestCase):
    """Tests for SentryHTTPServer route dispatch."""

    @classmethod
    def setUpClass(cls):
        from sentry.api.auth import Authenticator
        from sentry.api.server import create_server

        cls.port = _get_free_port()
        cls.auth = Authenticator(
            valid_token="test-token-xyz",
            session_ttl_seconds=60,
            max_attempts=5,
            lockout_seconds=60,
        )
        cls.server = create_server(
            host="127.0.0.1",
            port=cls.port,
            authenticator=cls.auth,
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_healthz_no_auth(self):
        status, _, body = _make_request(self.port, "GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")

    def test_unauthenticated_redirects_to_login(self):
        status, headers, _ = _make_request(self.port, "GET", "/dashboard.html")
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/login.html")

    def test_login_page_served_without_auth(self):
        status, headers, body = _make_request(self.port, "GET", "/login.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn(b"Sentry", body)

    def test_api_unauthenticated_returns_401(self):
        status, _, body = _make_request(self.port, "GET", "/api/v1/status")
        self.assertEqual(status, 401)
        data = json.loads(body)
        self.assertIn("error", data)

    def test_api_bearer_token_auth(self):
        headers = {"Authorization": "Bearer test-token-xyz"}
        status, _, body = _make_request(self.port, "GET", "/api/v1/status", headers)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "running")

    def test_api_wrong_token_returns_401(self):
        headers = {"Authorization": "Bearer wrong-token"}
        status, _, body = _make_request(self.port, "GET", "/api/v1/status", headers)
        self.assertEqual(status, 401)

    def test_api_session_cookie_auth(self):
        # Login first
        body = json.dumps({"token": "test-token-xyz"}).encode()
        status, headers, _ = _make_request(
            self.port, "POST", "/api/v1/login", body=body
        )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        # Extract sentry_session
        session_id = ""
        for part in cookie.split(";"):
            if "sentry_session=" in part:
                session_id = part.split("sentry_session=")[1].strip()
        self.assertTrue(session_id)

        # Use session cookie
        status, _, resp = _make_request(
            self.port, "GET", "/api/v1/status", cookie=f"sentry_session={session_id}"
        )
        self.assertEqual(status, 200)

    def test_dashboard_with_valid_session(self):
        # Login
        body = json.dumps({"token": "test-token-xyz"}).encode()
        _, headers, _ = _make_request(self.port, "POST", "/api/v1/login", body=body)
        cookie = headers.get("Set-Cookie", "")
        session_id = ""
        for part in cookie.split(";"):
            if "sentry_session=" in part:
                session_id = part.split("sentry_session=")[1].strip()

        # Access dashboard with session
        status, _, body = _make_request(
            self.port, "GET", "/dashboard.html", cookie=f"sentry_session={session_id}"
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Sentry", body)

    def test_login_post_success(self):
        body = json.dumps({"token": "test-token-xyz"}).encode()
        status, headers, resp = _make_request(
            self.port, "POST", "/api/v1/login", body=body
        )
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)
        data = json.loads(resp)
        self.assertEqual(data["status"], "ok")

    def test_login_post_wrong_token(self):
        body = json.dumps({"token": "wrong"}).encode()
        status, _, resp = _make_request(
            self.port, "POST", "/api/v1/login", body=body
        )
        self.assertEqual(status, 401)

    def test_threats_endpoint(self):
        headers = {"Authorization": "Bearer test-token-xyz"}
        status, _, body = _make_request(self.port, "GET", "/api/v1/threats", headers)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("threats", data)

    def test_topology_endpoint(self):
        headers = {"Authorization": "Bearer test-token-xyz"}
        status, _, body = _make_request(self.port, "GET", "/api/v1/topology", headers)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("devices", data)

    def test_404_for_unknown_route(self):
        headers = {"Authorization": "Bearer test-token-xyz"}
        status, _, body = _make_request(self.port, "GET", "/api/v1/nonexistent", headers)
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
