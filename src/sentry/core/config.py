"""Configuration loader and structured JSON logging setup.

Loads sentry.yaml and policy.yaml using minyaml parser.
Environment variables override YAML values (12-factor pattern):
    SENTRY_ONOS_HOST, SENTRY_ONOS_PORT, SENTRY_ONOS_USER, SENTRY_ONOS_PASS
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass

from sentry.core.minyaml import load_yaml_file


def _env_or(name: str, default: object) -> object:
    """Return the env var value if set, else the YAML/default value."""
    import os

    val = os.environ.get(name)
    return val if val is not None else default


@dataclass
class OnosConfig:
    """ONOS controller connection configuration."""

    host: str = "127.0.0.1"
    port: int = 8181
    use_https: bool = False
    username: str = "onos"
    password: str = "rocks"
    timeout: float = 5.0
    backoff_initial: float = 1.0
    backoff_multiplier: float = 2.0
    backoff_max_seconds: float = 30.0


@dataclass
class ApiConfig:
    """API server configuration."""

    host: str = "0.0.0.0"
    port: int = 9090
    auth_token: str = "dev-sentry-token-change-in-prod"
    session_ttl_seconds: int = 43200
    rate_limit_max_attempts: int = 5
    rate_limit_lockout_seconds: int = 60


@dataclass
class ServiceConfig:
    """Core service configuration."""

    name: str = "sentry"
    mode: str = "dry-run"  # "dry-run" or "enforce"
    poll_interval: float = 2.0
    warmup_windows: int = 5
    log_level: str = "INFO"


@dataclass
class LedgerConfig:
    """Audit ledger configuration."""

    path: str = "audit_ledger.jsonl"
    enabled: bool = True


@dataclass
class ThreatDetectorConfig:
    """Individual threat detector configuration."""

    enabled: bool = True
    threshold_pps: int = 0
    baseline_mad_factor: float = 3.0
    min_confidence: float = 0.85
    unique_ports_threshold: int = 0
    window_seconds: int = 5
    mac_conflict_threshold: int = 2
    packet_in_pps: int = 0
    table_utilization_pct: float = 0.0
    link_flap_threshold: int = 0
    alert_only: bool = False


@dataclass
class MitigationConfig:
    """Mitigation policy configuration."""

    default_ttl_seconds: int = 60
    max_ttl_seconds: int = 300
    prevent_gateway_quarantine: bool = True
    prevent_controller_port_drop: bool = True
    require_operator_ack_stage_4: bool = True
    max_simultaneous_mitigations: int = 10
    cooldown_period_seconds: int = 30


@dataclass
class SentryConfig:
    """Complete Sentry configuration."""

    service: ServiceConfig
    onos: OnosConfig
    api: ApiConfig
    ledger: LedgerConfig
    threats: dict[str, ThreatDetectorConfig]
    mitigation: MitigationConfig


class StructuredJsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging (NFR-5)."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Include extra fields from record.__dict__
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "stack_info",
            ]:
                log_entry[key] = value

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured JSON logging."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add JSON handler to stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(handler)


def load_config(
    sentry_yaml_path: str = "config/sentry.yaml",
    policy_yaml_path: str = "config/policy.yaml",
) -> SentryConfig:
    """Load configuration from YAML files."""
    sentry_data = load_yaml_file(sentry_yaml_path)
    policy_data = load_yaml_file(policy_yaml_path)

    # Parse service config
    service_dict = sentry_data.get("service", {})
    service = ServiceConfig(
        name=service_dict.get("name", "sentry"),
        mode=service_dict.get("mode", "dry-run"),
        poll_interval=service_dict.get("poll_interval", 2.0),
        warmup_windows=service_dict.get("warmup_windows", 5),
        log_level=service_dict.get("log_level", "INFO"),
    )

    # Parse ONOS config (env vars override YAML, 12-factor style)
    onos_dict = sentry_data.get("onos", {})
    auth_dict = onos_dict.get("auth", {})
    backoff_dict = onos_dict.get("backoff", {})
    onos = OnosConfig(
        host=_env_or("SENTRY_ONOS_HOST", onos_dict.get("host", "127.0.0.1")),
        port=int(_env_or("SENTRY_ONOS_PORT", onos_dict.get("port", 8181))),
        use_https=onos_dict.get("use_https", False),
        username=_env_or("SENTRY_ONOS_USER", auth_dict.get("username", "onos")),
        password=_env_or("SENTRY_ONOS_PASS", auth_dict.get("password", "rocks")),
        timeout=onos_dict.get("timeout", 5.0),
        backoff_initial=backoff_dict.get("initial", 1.0),
        backoff_multiplier=backoff_dict.get("multiplier", 2.0),
        backoff_max_seconds=backoff_dict.get("max_seconds", 30.0),
    )

    # Parse API config
    api_dict = sentry_data.get("api", {})
    rate_limit_dict = api_dict.get("rate_limit", {})
    api = ApiConfig(
        host=api_dict.get("host", "0.0.0.0"),
        port=api_dict.get("port", 9090),
        auth_token=api_dict.get("auth_token", "dev-sentry-token-change-in-prod"),
        session_ttl_seconds=api_dict.get("session_ttl_seconds", 43200),
        rate_limit_max_attempts=rate_limit_dict.get("max_attempts", 5),
        rate_limit_lockout_seconds=rate_limit_dict.get("lockout_seconds", 60),
    )

    # Parse ledger config
    ledger_dict = sentry_data.get("ledger", {})
    ledger = LedgerConfig(
        path=ledger_dict.get("path", "audit_ledger.jsonl"),
        enabled=ledger_dict.get("enabled", True),
    )

    # Parse threat detector configs
    threats_dict = policy_data.get("threats", {})
    threats = {}
    for threat_name, threat_cfg in threats_dict.items():
        threats[threat_name] = ThreatDetectorConfig(
            enabled=threat_cfg.get("enabled", True),
            threshold_pps=threat_cfg.get("threshold_pps", 0),
            baseline_mad_factor=threat_cfg.get("baseline_mad_factor", 3.0),
            min_confidence=threat_cfg.get("min_confidence", 0.85),
            unique_ports_threshold=threat_cfg.get("unique_ports_threshold", 0),
            window_seconds=threat_cfg.get("window_seconds", 5),
            mac_conflict_threshold=threat_cfg.get("mac_conflict_threshold", 2),
            packet_in_pps=threat_cfg.get("packet_in_pps", 0),
            table_utilization_pct=threat_cfg.get("table_utilization_pct", 0.0),
            link_flap_threshold=threat_cfg.get("link_flap_threshold", 0),
            alert_only=threat_cfg.get("alert_only", False),
        )

    # Parse mitigation config
    mitigation_dict = policy_data.get("mitigation", {})
    safety_rails = mitigation_dict.get("safety_rails", {})
    mitigation = MitigationConfig(
        default_ttl_seconds=mitigation_dict.get("default_ttl_seconds", 60),
        max_ttl_seconds=mitigation_dict.get("max_ttl_seconds", 300),
        prevent_gateway_quarantine=safety_rails.get("prevent_gateway_quarantine", True),
        prevent_controller_port_drop=safety_rails.get("prevent_controller_port_drop", True),
        require_operator_ack_stage_4=safety_rails.get("require_operator_ack_stage_4", True),
        max_simultaneous_mitigations=safety_rails.get("max_simultaneous_mitigations", 10),
        cooldown_period_seconds=safety_rails.get("cooldown_period_seconds", 30),
    )

    return SentryConfig(
        service=service,
        onos=onos,
        api=api,
        ledger=ledger,
        threats=threats,
        mitigation=mitigation,
    )
