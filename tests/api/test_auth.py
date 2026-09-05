"""Tests for sentry.api.auth — SessionStore, RateLimiter, Authenticator."""

from __future__ import annotations

import time
import unittest


class TestSessionStore(unittest.TestCase):
    """Tests for SessionStore."""

    def setUp(self):
        from sentry.api.auth import SessionStore
        self.store = SessionStore(ttl_seconds=60)

    def test_create_returns_session_id(self):
        sid = self.store.create("test-token")
        self.assertIsInstance(sid, str)
        self.assertEqual(len(sid), 32)  # token_hex(16) = 32 hex chars

    def test_validate_returns_true_for_valid_session(self):
        sid = self.store.create("test-token")
        self.assertTrue(self.store.validate(sid))

    def test_validate_returns_false_for_invalid_session(self):
        self.assertFalse(self.store.validate("nonexistent"))

    def test_validate_returns_false_after_ttl(self):
        store = __import__("sentry.api.auth", fromlist=["SessionStore"]).SessionStore(ttl_seconds=0)
        sid = store.create("test-token")
        time.sleep(0.01)
        self.assertFalse(store.validate(sid))

    def test_destroy_removes_session(self):
        sid = self.store.create("test-token")
        self.store.destroy(sid)
        self.assertFalse(self.store.validate(sid))

    def test_destroy_nonexistent_is_noop(self):
        self.store.destroy("nonexistent")  # should not raise

    def test_cleanup_removes_expired(self):
        store = __import__("sentry.api.auth", fromlist=["SessionStore"]).SessionStore(ttl_seconds=0)
        store.create("token1")
        store.create("token2")
        time.sleep(0.01)
        removed = store.cleanup()
        self.assertEqual(removed, 2)
        self.assertEqual(store.get_count(), 0)

    def test_cleanup_leaves_valid_sessions(self):
        self.store.create("token1")
        self.store.create("token2")
        removed = self.store.cleanup()
        self.assertEqual(removed, 0)
        self.assertEqual(self.store.get_count(), 2)

    def test_get_count(self):
        self.assertEqual(self.store.get_count(), 0)
        self.store.create("token1")
        self.assertEqual(self.store.get_count(), 1)
        self.store.create("token2")
        self.assertEqual(self.store.get_count(), 2)


class TestRateLimiter(unittest.TestCase):
    """Tests for RateLimiter."""

    def setUp(self):
        from sentry.api.auth import RateLimiter
        self.limiter = RateLimiter(max_attempts=3, lockout_seconds=60)

    def test_not_locked_initially(self):
        self.assertFalse(self.limiter.is_locked("10.0.0.1"))

    def test_locked_after_max_attempts(self):
        for _ in range(3):
            self.limiter.record_failure("10.0.0.1")
        self.assertTrue(self.limiter.is_locked("10.0.0.1"))

    def test_not_locked_below_max(self):
        for _ in range(2):
            self.limiter.record_failure("10.0.0.1")
        self.assertFalse(self.limiter.is_locked("10.0.0.1"))

    def test_clear_resets_attempts(self):
        for _ in range(3):
            self.limiter.record_failure("10.0.0.1")
        self.assertTrue(self.limiter.is_locked("10.0.0.1"))
        self.limiter.clear("10.0.0.1")
        self.assertFalse(self.limiter.is_locked("10.0.0.1"))

    def test_separate_ips(self):
        for _ in range(3):
            self.limiter.record_failure("10.0.0.1")
        self.assertTrue(self.limiter.is_locked("10.0.0.1"))
        self.assertFalse(self.limiter.is_locked("10.0.0.2"))

    def test_get_remaining_lockout(self):
        self.assertEqual(self.limiter.get_remaining_lockout("10.0.0.1"), 0)
        for _ in range(3):
            self.limiter.record_failure("10.0.0.1")
        remaining = self.limiter.get_remaining_lockout("10.0.0.1")
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 60)

    def test_lockout_expires(self):
        limiter = __import__("sentry.api.auth", fromlist=["RateLimiter"]).RateLimiter(
            max_attempts=2, lockout_seconds=0
        )
        limiter.record_failure("10.0.0.1")
        limiter.record_failure("10.0.0.1")
        time.sleep(0.01)
        self.assertFalse(limiter.is_locked("10.0.0.1"))


class TestAuthenticator(unittest.TestCase):
    """Tests for Authenticator."""

    def setUp(self):
        from sentry.api.auth import Authenticator
        self.auth = Authenticator(
            valid_token="secret-token-123",
            session_ttl_seconds=60,
            max_attempts=3,
            lockout_seconds=60,
        )

    def test_validate_token_correct(self):
        self.assertTrue(self.auth.validate_token("secret-token-123"))

    def test_validate_token_wrong(self):
        self.assertFalse(self.auth.validate_token("wrong-token"))

    def test_login_success(self):
        sid = self.auth.login("secret-token-123", "10.0.0.1")
        self.assertIsNotNone(sid)
        self.assertIsInstance(sid, str)

    def test_login_failure_wrong_token(self):
        sid = self.auth.login("wrong-token", "10.0.0.1")
        self.assertIsNone(sid)

    def test_login_creates_valid_session(self):
        sid = self.auth.login("secret-token-123", "10.0.0.1")
        self.assertTrue(self.auth.check_session(sid))

    def test_logout_destroys_session(self):
        sid = self.auth.login("secret-token-123", "10.0.0.1")
        self.auth.logout(sid)
        self.assertFalse(self.auth.check_session(sid))

    def test_rate_limit_after_failures(self):
        for _ in range(3):
            self.auth.login("wrong-token", "10.0.0.2")
        # Now locked — even correct token fails
        sid = self.auth.login("secret-token-123", "10.0.0.2")
        self.assertIsNone(sid)

    def test_successful_login_clears_rate_limit(self):
        # 2 failures (below limit)
        self.auth.login("wrong", "10.0.0.3")
        self.auth.login("wrong", "10.0.0.3")
        # Successful login clears
        sid = self.auth.login("secret-token-123", "10.0.0.3")
        self.assertIsNotNone(sid)
        # Can fail again without being locked
        self.auth.login("wrong", "10.0.0.3")
        self.assertFalse(self.auth.rate_limiter.is_locked("10.0.0.3"))

    def test_check_request_bearer_token(self):
        headers = {"Authorization": "Bearer secret-token-123"}
        self.assertTrue(self.auth.check_request(headers))

    def test_check_request_bearer_wrong(self):
        headers = {"Authorization": "Bearer wrong"}
        self.assertFalse(self.auth.check_request(headers))

    def test_check_request_session_cookie(self):
        sid = self.auth.login("secret-token-123", "10.0.0.4")
        cookies = {"sentry_session": sid}
        self.assertTrue(self.auth.check_request({}, cookies))

    def test_check_request_session_invalid(self):
        cookies = {"sentry_session": "fake-session"}
        self.assertFalse(self.auth.check_request({}, cookies))

    def test_check_request_no_auth(self):
        self.assertFalse(self.auth.check_request({}))


if __name__ == "__main__":
    unittest.main()
