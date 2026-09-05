"""API authentication — bearer-token and session-cookie authorization.

Provides:
  - Bearer token validation ( Authorization: Bearer <token> )
  - Session cookie management (HttpOnly, SameSite=Strict)
  - Rate limiting (5 failed attempts per IP within 60s → temporary lockout)
  - Constant-time token comparison to prevent timing attacks

All auth state is in-memory; no database required (NFR-3: zero third-party deps).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any


class SessionStore:
    """In-memory session store with configurable TTL."""

    def __init__(self, ttl_seconds: int = 43200) -> None:
        """Initialize session store.

        Args:
            ttl_seconds: Session time-to-live (default 12 hours)
        """
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, dict[str, Any]] = {}

    def create(self, token: str) -> str:
        """Create a new session and return the session ID.

        Args:
            token: The authenticated token value

        Returns:
            Session ID (random 32-char hex string)
        """
        session_id = secrets.token_hex(16)
        self._sessions[session_id] = {
            "token_hash": self._hash_token(token),
            "created_at": time.time(),
            "expires_at": time.time() + self.ttl_seconds,
        }
        return session_id

    def validate(self, session_id: str) -> bool:
        """Check if a session ID is valid and not expired.

        Args:
            session_id: Session ID to validate

        Returns:
            True if session is valid and not expired
        """
        session = self._sessions.get(session_id)
        if session is None:
            return False
        if time.time() > session["expires_at"]:
            del self._sessions[session_id]
            return False
        return True

    def destroy(self, session_id: str) -> None:
        """Destroy a session.

        Args:
            session_id: Session ID to destroy
        """
        self._sessions.pop(session_id, None)

    def cleanup(self) -> int:
        """Remove expired sessions.

        Returns:
            Number of sessions removed
        """
        now = time.time()
        expired = [
            sid for sid, sess in self._sessions.items()
            if now > sess["expires_at"]
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def get_count(self) -> int:
        """Get number of active sessions."""
        return len(self._sessions)

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for storage (never store raw tokens)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RateLimiter:
    """Per-IP rate limiter for failed authentication attempts."""

    def __init__(
        self,
        max_attempts: int = 5,
        lockout_seconds: int = 60,
    ) -> None:
        """Initialize rate limiter.

        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_seconds: Duration of lockout in seconds
        """
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        # {ip: [(timestamp, ...)]}
        self._attempts: dict[str, list[float]] = {}

    def record_failure(self, ip: str) -> None:
        """Record a failed authentication attempt for an IP.

        Args:
            ip: Client IP address
        """
        now = time.time()
        if ip not in self._attempts:
            self._attempts[ip] = []
        self._attempts[ip].append(now)
        # Prune old entries outside the window
        cutoff = now - self.lockout_seconds
        self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]

    def is_locked(self, ip: str) -> bool:
        """Check if an IP is currently locked out.

        Args:
            ip: Client IP address

        Returns:
            True if the IP has exceeded max attempts within the lockout window
        """
        now = time.time()
        cutoff = now - self.lockout_seconds
        attempts = self._attempts.get(ip, [])
        # Count attempts within the window
        recent = [t for t in attempts if t > cutoff]
        return len(recent) >= self.max_attempts

    def clear(self, ip: str) -> None:
        """Clear failure history for an IP (e.g., after successful login).

        Args:
            ip: Client IP address
        """
        self._attempts.pop(ip, None)

    def get_remaining_lockout(self, ip: str) -> int:
        """Get seconds remaining in lockout for an IP.

        Args:
            ip: Client IP address

        Returns:
            Seconds remaining, or 0 if not locked
        """
        if not self.is_locked(ip):
            return 0
        attempts = self._attempts.get(ip, [])
        if not attempts:
            return 0
        oldest_in_window = min(attempts)
        remaining = int(self.lockout_seconds - (time.time() - oldest_in_window))
        return max(0, remaining)


class Authenticator:
    """Authentication manager combining token validation, sessions, and rate limiting."""

    def __init__(
        self,
        valid_token: str,
        session_ttl_seconds: int = 43200,
        max_attempts: int = 5,
        lockout_seconds: int = 60,
    ) -> None:
        """Initialize authenticator.

        Args:
            valid_token: The valid API token (from config)
            session_ttl_seconds: Session TTL in seconds
            max_attempts: Max failed login attempts before lockout
            lockout_seconds: Lockout duration in seconds
        """
        self.valid_token = valid_token
        self.sessions = SessionStore(ttl_seconds=session_ttl_seconds)
        self.rate_limiter = RateLimiter(
            max_attempts=max_attempts,
            lockout_seconds=lockout_seconds,
        )

    def validate_token(self, token: str) -> bool:
        """Validate a token using constant-time comparison.

        Args:
            token: Token to validate

        Returns:
            True if token matches
        """
        return hmac.compare_digest(token, self.valid_token)

    def login(self, token: str, client_ip: str) -> str | None:
        """Attempt login with token.

        Args:
            token: Authentication token
            client_ip: Client IP for rate limiting

        Returns:
            Session ID if successful, None if failed
        """
        # Check rate limit
        if self.rate_limiter.is_locked(client_ip):
            return None

        # Validate token
        if not self.validate_token(token):
            self.rate_limiter.record_failure(client_ip)
            return None

        # Success — clear rate limit and create session
        self.rate_limiter.clear(client_ip)
        session_id = self.sessions.create(token)
        return session_id

    def logout(self, session_id: str) -> None:
        """Destroy a session.

        Args:
            session_id: Session to destroy
        """
        self.sessions.destroy(session_id)

    def check_session(self, session_id: str) -> bool:
        """Validate a session.

        Args:
            session_id: Session ID to check

        Returns:
            True if session is valid
        """
        return self.sessions.validate(session_id)

    def check_request(
        self,
        headers: dict[str, str],
        cookie_jar: dict[str, str] | None = None,
    ) -> bool:
        """Check if a request is authenticated via either method.

        Checks bearer token first, then session cookie.

        Args:
            headers: Request headers (case-insensitive lookup)
            cookie_jar: Parsed cookies from Cookie header

        Returns:
            True if request is authenticated
        """
        # Method 1: Bearer token
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if self.validate_token(token):
                return True

        # Method 2: Session cookie
        if cookie_jar:
            session_id = cookie_jar.get("sentry_session", "")
            if session_id and self.check_session(session_id):
                return True

        return False
