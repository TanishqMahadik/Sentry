"""API route handlers for Sentry dashboard and control.

All routes return (status_code, headers, body_bytes) tuples.
Routes requiring auth are decorated with @require_auth.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from sentry.api.auth import Authenticator
from sentry.core.models import ThreatVerdict

# Type for route handlers
RouteHandler = Callable[..., tuple[int, dict[str, str], bytes]]


def _json_response(
    status: int, data: Any, content_type: str = "application/json"
) -> tuple[int, dict[str, str], bytes]:
    """Build a JSON HTTP response.

    Args:
        status: HTTP status code
        data: Data to serialize as JSON
        content_type: Content-Type header

    Returns:
        (status, headers, body) tuple
    """
    body = json.dumps(data).encode("utf-8")
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Cache-Control": "no-store",
    }
    return status, headers, body


def _html_response(
    status: int, html: str
) -> tuple[int, dict[str, str], bytes]:
    """Build an HTML HTTP response."""
    body = html.encode("utf-8")
    headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Length": str(len(body)),
    }
    return status, headers, body


def _redirect(url: str) -> tuple[int, dict[str, str], bytes]:
    """Build a redirect response."""
    headers = {"Location": url, "Content-Length": "0"}
    return 302, headers, b""


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse Cookie header into a dict.

    Args:
        cookie_header: Raw Cookie header value

    Returns:
        Dict of name -> value
    """
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def make_login_handler(
    authenticator: Authenticator,
) -> RouteHandler:
    """Create the POST /api/v1/login handler.

    Args:
        authenticator: Authenticator instance

    Returns:
        Route handler function
    """

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        if method != "POST":
            return _json_response(405, {"error": "Method not allowed"})

        # Check rate limit first
        if authenticator.rate_limiter.is_locked(client_ip):
            remaining = authenticator.rate_limiter.get_remaining_lockout(client_ip)
            return _json_response(
                429,
                {"error": f"Too many attempts. Try again in {remaining}s."},
            )

        # Parse body
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return _json_response(400, {"error": "Invalid JSON"})

        token = data.get("token", "")
        if not token:
            return _json_response(400, {"error": "Token required"})

        # Attempt login
        session_id = authenticator.login(token, client_ip)
        if session_id is None:
            remaining = 5 - len(
                authenticator.rate_limiter._attempts.get(client_ip, [])
            )
            return _json_response(
                401,
                {
                    "error": "Invalid token",
                    "attempts_remaining": max(0, remaining),
                },
            )

        # Build response with session cookie
        headers = {
            "Content-Type": "application/json",
            "Set-Cookie": (
                f"sentry_session={session_id}; "
                f"Path=/; "
                f"HttpOnly; "
                f"SameSite=Strict; "
                f"Max-Age={authenticator.sessions.ttl_seconds}"
            ),
        }
        body = json.dumps({"status": "ok", "session_id": session_id}).encode("utf-8")
        headers["Content-Length"] = str(len(body))
        return 200, headers, body

    return handler


def make_logout_handler(
    authenticator: Authenticator,
) -> RouteHandler:
    """Create the POST /api/v1/logout handler."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        cookie_header = headers.get("Cookie", "")
        cookies = _parse_cookies(cookie_header)
        session_id = cookies.get("sentry_session", "")
        if session_id:
            authenticator.logout(session_id)

        resp_headers = {
            "Content-Type": "application/json",
            "Set-Cookie": (
                "sentry_session=; Path=/; Max-Age=0; "
                "HttpOnly; SameSite=Strict"
            ),
        }
        resp_body = json.dumps({"status": "ok"}).encode("utf-8")
        resp_headers["Content-Length"] = str(len(resp_body))
        return 200, resp_headers, resp_body

    return handler


def make_status_handler() -> RouteHandler:
    """Create the GET /api/v1/status handler."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        return _json_response(200, {
            "status": "running",
            "version": "0.1.0",
            "uptime_seconds": int(time.time()),
            "mode": "dry-run",
        })

    return handler


def make_threats_handler(
    scorer: Any = None,
    threats_source: Callable[[], list[ThreatVerdict]] | None = None,
) -> RouteHandler:
    """Create the GET /api/v1/threats handler.

    When a scorer and a threat source are supplied, each threat entry is
    annotated with an ``advisory`` key from the ML advisory scorer (Phase 8).
    Without them the handler mirrors the current empty placeholder shape.

    Args:
        scorer: Optional AdvisoryScorer (attaches the advisory field)
        threats_source: Optional provider of active ThreatVerdicts

    Returns:
        Route handler function
    """

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        threats = threats_source() if threats_source is not None else []
        if scorer is not None and getattr(scorer, "available", False):
            # Annotate each threat with the ML advisory verdict.
            port_metrics: dict[str, dict[str, float]] = {}
            flow_metrics: dict[str, float] = {}
            entries = scorer.attach_to_threats(threats, port_metrics, flow_metrics)
        else:
            entries = [
                {
                    "threat_type": t.threat_type,
                    "subject_id": t.subject_id,
                    "severity": t.severity,
                    "confidence": t.confidence,
                    "timestamp": t.timestamp,
                    "evidence": t.evidence,
                    "message": t.message,
                }
                for t in threats
            ]
        return _json_response(200, {"threats": entries, "count": len(entries)})

    return handler


def make_mitigations_handler(
    executor: Any = None,
) -> RouteHandler:
    """Create the GET /api/v1/mitigations handler."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        if executor is None:
            return _json_response(200, {"mitigations": [], "count": 0})
        actions = executor.get_applied_actions()
        items = []
        for a in actions:
            if a.status == "applied":
                items.append({
                    "action_id": a.action_id,
                    "subject_id": a.threat_verdict.subject_id,
                    "stage": a.stage,
                    "action_type": a.action_type,
                    "device_id": a.device_id,
                    "applied_at": a.applied_at,
                    "expires_at": a.expires_at,
                    "status": a.status,
                })
        return _json_response(200, {"mitigations": items, "count": len(items)})

    return handler


def make_revoke_handler(
    executor: Any = None,
) -> RouteHandler:
    """Create the POST /api/v1/mitigations/{id}/revoke handler."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        if method != "POST":
            return _json_response(405, {"error": "Method not allowed"})

        if executor is None:
            return _json_response(503, {"error": "Executor not available"})

        # Extract action_id from path: /api/v1/mitigations/{id}/revoke
        parts = path.strip("/").split("/")
        if len(parts) < 5:
            return _json_response(400, {"error": "Missing action ID"})
        action_id = parts[3]

        # Find the action
        for action in executor.get_applied_actions():
            if action.action_id == action_id and action.status == "applied":
                success = executor.revoke(action)
                if success:
                    return _json_response(200, {
                        "status": "revoked",
                        "action_id": action_id,
                    })
                else:
                    return _json_response(500, {"error": "Revoke failed"})

        return _json_response(404, {"error": "Action not found"})

    return handler


def make_topology_handler() -> RouteHandler:
    """Create the GET /api/v1/topology handler."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        # Placeholder — will be wired to live topology in production
        return _json_response(200, {
            "devices": [],
            "hosts": [],
            "links": [],
        })

    return handler


def make_replay_handler() -> RouteHandler:
    """Create the GET /api/v1/replay handler for offline demo mode."""

    def handler(
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        client_ip: str,
    ) -> tuple[int, dict[str, str], bytes]:
        from sentry.sim.replay import ReplayEngine
        from sentry.sim.scenarios import SCENARIOS

        # Parse query params from path
        query = {}
        if "?" in path:
            qs = path.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    query[k] = v

        scenario = query.get("scenario", "all")
        engine = ReplayEngine()

        if scenario == "all":
            results = {}
            for name in SCENARIOS:
                result = engine.replay_scenario(name, max_ticks=15, mad_threshold=2.0)
                results[name] = {
                    "ticks": result.ticks_processed,
                    "anomalies": len(result.anomalies_detected),
                    "detection_tick": result.detection_tick,
                }
            return _json_response(200, {"results": results})
        else:
            if scenario not in SCENARIOS:
                return _json_response(400, {"error": f"Unknown scenario: {scenario}"})
            result = engine.replay_scenario(scenario, max_ticks=15, mad_threshold=2.0)
            return _json_response(200, {
                "scenario": scenario,
                "ticks": result.ticks_processed,
                "anomalies": len(result.anomalies_detected),
                "detection_tick": result.detection_tick,
            })

    return handler
