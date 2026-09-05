"""Tests for sentry.api.routes — route handlers."""

from __future__ import annotations

import json
import unittest


class TestJsonResponse(unittest.TestCase):
    """Tests for _json_response helper."""

    def test_json_response_status(self):
        from sentry.api.routes import _json_response
        status, _, body = _json_response(200, {"key": "value"})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["key"], "value")

    def test_json_response_headers(self):
        from sentry.api.routes import _json_response
        _, headers, _ = _json_response(404, {"error": "not found"})
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("Cache-Control", headers)


class TestParseCookies(unittest.TestCase):
    """Tests for _parse_cookies helper."""

    def test_parse_single_cookie(self):
        from sentry.api.routes import _parse_cookies
        cookies = _parse_cookies("sentry_session=abc123")
        self.assertEqual(cookies["sentry_session"], "abc123")

    def test_parse_multiple_cookies(self):
        from sentry.api.routes import _parse_cookies
        cookies = _parse_cookies("foo=bar; sentry_session=abc123; baz=qux")
        self.assertEqual(cookies["foo"], "bar")
        self.assertEqual(cookies["sentry_session"], "abc123")
        self.assertEqual(cookies["baz"], "qux")

    def test_parse_empty(self):
        from sentry.api.routes import _parse_cookies
        cookies = _parse_cookies("")
        self.assertEqual(cookies, {})

    def test_parse_whitespace(self):
        from sentry.api.routes import _parse_cookies
        cookies = _parse_cookies("  sentry_session = abc123  ")
        self.assertEqual(cookies["sentry_session"], "abc123")


class TestStatusHandler(unittest.TestCase):
    """Tests for make_status_handler."""

    def test_returns_200(self):
        from sentry.api.routes import make_status_handler
        handler = make_status_handler()
        status, _, body = handler("GET", "/api/v1/status", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "running")
        self.assertIn("version", data)


class TestThreatsHandler(unittest.TestCase):
    """Tests for make_threats_handler."""

    def test_returns_empty_threats(self):
        from sentry.api.routes import make_threats_handler
        handler = make_threats_handler()
        status, _, body = handler("GET", "/api/v1/threats", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 0)

    def test_threats_without_scorer_have_no_advisory(self):
        from sentry.api.routes import make_threats_handler
        from sentry.core.models import ThreatVerdict

        threat = ThreatVerdict(
            threat_type="syn_flood",
            subject_id="10.0.0.5",
            severity="high",
            confidence=0.9,
            timestamp=123,
            evidence={"pps_rx": 5000.0},
            message="SYN flood detected",
        )
        handler = make_threats_handler(scorer=None, threats_source=lambda: [threat])
        status, _, body = handler("GET", "/api/v1/threats", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 1)
        self.assertNotIn("advisory", data["threats"][0])

    def test_threats_with_scorer_carry_advisory(self):
        from sentry.api.routes import make_threats_handler
        from sentry.core.models import ThreatVerdict
        from tests.ml._helpers import attack_metrics, build_test_scorer

        threat = ThreatVerdict(
            threat_type="syn_flood",
            subject_id="10.0.0.5",
            severity="high",
            confidence=0.9,
            timestamp=123,
            evidence={"pps_rx": 5000.0},
            message="SYN flood detected",
        )
        scorer = build_test_scorer()
        port_metrics, flow_metrics = attack_metrics()
        handler = make_threats_handler(scorer=scorer, threats_source=lambda: [threat])
        status, _, body = handler("GET", "/api/v1/threats", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 1)
        entry = data["threats"][0]
        self.assertEqual(entry["threat_type"], "syn_flood")
        self.assertIn("advisory", entry)
        self.assertIn("band", entry["advisory"])


class TestTopologyHandler(unittest.TestCase):
    """Tests for make_topology_handler."""

    def test_returns_empty_topology(self):
        from sentry.api.routes import make_topology_handler
        handler = make_topology_handler()
        status, _, body = handler("GET", "/api/v1/topology", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("devices", data)


class TestMitigationsHandler(unittest.TestCase):
    """Tests for make_mitigations_handler."""

    def test_no_executor_returns_empty(self):
        from sentry.api.routes import make_mitigations_handler
        handler = make_mitigations_handler(executor=None)
        status, _, body = handler("GET", "/api/v1/mitigations", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["count"], 0)


class TestRevokeHandler(unittest.TestCase):
    """Tests for make_revoke_handler."""

    def test_no_executor_returns_503(self):
        from sentry.api.routes import make_revoke_handler
        handler = make_revoke_handler(executor=None)
        status, _, body = handler("POST", "/api/v1/mitigations/abc/revoke", {}, b"", "10.0.0.1")
        self.assertEqual(status, 503)

    def test_wrong_method_returns_405(self):
        from sentry.api.routes import make_revoke_handler
        handler = make_revoke_handler(executor=None)
        status, _, body = handler("GET", "/api/v1/mitigations/abc/revoke", {}, b"", "10.0.0.1")
        self.assertEqual(status, 405)


class TestLoginHandler(unittest.TestCase):
    """Tests for make_login_handler."""

    def setUp(self):
        from sentry.api.auth import Authenticator
        from sentry.api.routes import make_login_handler
        self.auth = Authenticator(valid_token="test-token", max_attempts=5, lockout_seconds=60)
        self.handler = make_login_handler(self.auth)

    def test_wrong_method_returns_405(self):
        status, _, _ = self.handler("GET", "/api/v1/login", {}, b"", "10.0.0.1")
        self.assertEqual(status, 405)

    def test_empty_body_returns_400(self):
        status, _, body = self.handler("POST", "/api/v1/login", {}, b"", "10.0.0.1")
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn("error", data)

    def test_invalid_json_returns_400(self):
        status, _, _ = self.handler("POST", "/api/v1/login", {}, b"not-json", "10.0.0.1")
        self.assertEqual(status, 400)

    def test_wrong_token_returns_401(self):
        body = json.dumps({"token": "wrong"}).encode()
        status, _, resp = self.handler("POST", "/api/v1/login", {}, body, "10.0.0.1")
        self.assertEqual(status, 401)
        data = json.loads(resp)
        self.assertIn("attempts_remaining", data)

    def test_correct_token_returns_200(self):
        body = json.dumps({"token": "test-token"}).encode()
        status, headers, resp = self.handler("POST", "/api/v1/login", {}, body, "10.0.0.1")
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", headers)
        self.assertIn("sentry_session=", headers["Set-Cookie"])
        data = json.loads(resp)
        self.assertEqual(data["status"], "ok")


class TestLogoutHandler(unittest.TestCase):
    """Tests for make_logout_handler."""

    def setUp(self):
        from sentry.api.auth import Authenticator
        from sentry.api.routes import make_logout_handler
        self.auth = Authenticator(valid_token="test-token", max_attempts=5, lockout_seconds=60)
        self.handler = make_logout_handler(self.auth)

    def test_logout_clears_cookie(self):
        sid = self.auth.login("test-token", "10.0.0.1")
        cookie_header = f"sentry_session={sid}"
        status, headers, body = self.handler(
            "POST", "/api/v1/logout", {"Cookie": cookie_header}, b"", "10.0.0.1"
        )
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])

    def test_logout_without_session(self):
        status, _, _ = self.handler("POST", "/api/v1/logout", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)


class TestReplayHandler(unittest.TestCase):
    """Tests for make_replay_handler."""

    def test_replay_all(self):
        from sentry.api.routes import make_replay_handler
        handler = make_replay_handler()
        status, _, body = handler("GET", "/api/v1/replay?scenario=all", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("results", data)

    def test_replay_single_scenario(self):
        from sentry.api.routes import make_replay_handler
        handler = make_replay_handler()
        status, _, body = handler("GET", "/api/v1/replay?scenario=syn_flood", {}, b"", "10.0.0.1")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["scenario"], "syn_flood")

    def test_replay_unknown_scenario(self):
        from sentry.api.routes import make_replay_handler
        handler = make_replay_handler()
        status, _, body = handler("GET", "/api/v1/replay?scenario=unknown", {}, b"", "10.0.0.1")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
