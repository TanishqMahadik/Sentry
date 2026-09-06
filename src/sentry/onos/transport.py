"""HTTP transport layer for ONOS REST API communication.

Uses stdlib urllib (NFR-3: zero third-party dependencies).
Includes FakeTransport for offline testing and simulation.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any


class HttpTransport(ABC):
    """Abstract base class for HTTP transport."""

    @abstractmethod
    def get(self, url: str) -> dict[str, Any]:
        """Perform HTTP GET request and return parsed JSON."""
        pass

    @abstractmethod
    def post(self, url: str, data: dict[str, Any]) -> dict[str, Any]:
        """Perform HTTP POST request and return parsed JSON."""
        pass

    @abstractmethod
    def delete(self, url: str) -> dict[str, Any]:
        """Perform HTTP DELETE request and return parsed JSON."""
        pass


class UrllibTransport(HttpTransport):
    """Production HTTP transport using stdlib urllib."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 5.0,
        backoff_initial: float = 1.0,
        backoff_multiplier: float = 2.0,
        backoff_max: float = 30.0,
    ) -> None:
        """Initialize urllib-based HTTP transport.

        Args:
            base_url: Base URL (e.g., http://127.0.0.1:8181/onos/v1)
            username: Basic Auth username
            password: Basic Auth password
            timeout: Request timeout in seconds
            backoff_initial: Initial backoff delay on failure
            backoff_multiplier: Exponential backoff multiplier
            backoff_max: Maximum backoff delay
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.backoff_initial = backoff_initial
        self.backoff_multiplier = backoff_multiplier
        self.backoff_max = backoff_max

        # Prepare Basic Auth header
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        self.auth_header = f"Basic {encoded}"

    def _request(
        self,
        method: str,
        url: str,
        data: dict[str, Any] | None = None,
        retry: bool = True,
    ) -> dict[str, Any]:
        """Internal method to perform HTTP request with exponential backoff."""
        full_url = f"{self.base_url}{url}"
        headers = {
            "Authorization": self.auth_header,
            "Accept": "application/json",
        }
        # Only send Content-Type on requests with a body (POST/PUT/PATCH)
        if data is not None:
            headers["Content-Type"] = "application/json"

        body = json.dumps(data).encode("utf-8") if data else None
        request = urllib.request.Request(
            full_url, data=body, headers=headers, method=method
        )

        backoff_delay = self.backoff_initial
        attempts = 0
        max_attempts = 5 if retry else 1

        while attempts < max_attempts:
            attempts += 1
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    response_body = response.read().decode("utf-8")
                    if not response_body.strip():
                        return {}
                    data = json.loads(response_body)
                    return data if isinstance(data, dict) else {}

            except urllib.error.HTTPError as e:
                if e.code in (401, 403, 404):
                    # Don't retry auth failures or not found
                    raise ConnectionError(f"HTTP {e.code}: {e.reason}") from e
                if attempts >= max_attempts:
                    raise ConnectionError(f"HTTP {e.code}: {e.reason}") from e

            except urllib.error.URLError as e:
                if attempts >= max_attempts:
                    raise ConnectionError(f"Connection failed: {e.reason}") from e

            except Exception as e:
                if attempts >= max_attempts:
                    raise ConnectionError(f"Request failed: {e}") from e

            # Exponential backoff
            time.sleep(backoff_delay)
            backoff_delay = min(backoff_delay * self.backoff_multiplier, self.backoff_max)

        raise ConnectionError(f"Max retry attempts ({max_attempts}) exceeded")

    def get(self, url: str) -> dict[str, Any]:
        """Perform HTTP GET request."""
        return self._request("GET", url)

    def post(self, url: str, data: dict[str, Any]) -> dict[str, Any]:
        """Perform HTTP POST request."""
        return self._request("POST", url, data=data)

    def delete(self, url: str) -> dict[str, Any]:
        """Perform HTTP DELETE request."""
        return self._request("DELETE", url)


class FakeTransport(HttpTransport):
    """Mock transport for offline testing and simulation.

    Returns pre-loaded fixture data instead of making real HTTP calls.
    Used in Phase 3 offline simulation and replay harness.
    """

    def __init__(self) -> None:
        """Initialize fake transport with empty fixture registry."""
        self.fixtures: dict[str, dict[str, Any]] = {}
        self.call_log: list[tuple[str, str, dict[str, Any] | None]] = []

    def register_fixture(self, url: str, response: dict[str, Any]) -> None:
        """Register a fixture response for a given URL pattern."""
        self.fixtures[url] = response

    def get(self, url: str) -> dict[str, Any]:
        """Return fixture data for GET request."""
        self.call_log.append(("GET", url, None))
        if url in self.fixtures:
            return self.fixtures[url]
        # Default empty responses for common endpoints
        if "/devices" in url:
            return {"devices": []}
        if "/hosts" in url:
            return {"hosts": []}
        if "/links" in url:
            return {"links": []}
        if "/flows" in url:
            return {"flows": []}
        if "/statistics" in url:
            return {"statistics": []}
        return {}

    def post(self, url: str, data: dict[str, Any]) -> dict[str, Any]:
        """Log POST request and return empty success response."""
        self.call_log.append(("POST", url, data))
        return {"success": True}

    def delete(self, url: str) -> dict[str, Any]:
        """Log DELETE request and return empty success response."""
        self.call_log.append(("DELETE", url, None))
        return {"success": True}

    def get_call_log(self) -> list[tuple[str, str, dict[str, Any] | None]]:
        """Return list of all HTTP calls made (for test assertions)."""
        return self.call_log

    def clear_log(self) -> None:
        """Clear the call log."""
        self.call_log.clear()
