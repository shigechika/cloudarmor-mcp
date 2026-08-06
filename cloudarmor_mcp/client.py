"""Cloud Logging queries for Cloud Armor (http_load_balancer) log entries.

The Google client library is imported lazily so unit tests can exercise
filter building and aggregation without the dependency installed or any
network access.
"""

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


class CloudArmorError(Exception):
    """Raised for configuration or Cloud Logging API errors."""


@dataclass
class Config:
    """Runtime configuration resolved from environment variables."""

    project: str
    backend_services: list[str] = field(default_factory=list)
    home_region: str | None = None

    @classmethod
    def from_env(cls) -> "Config":
        project = os.environ.get("CLOUDARMOR_PROJECT", "")
        if not project:
            raise CloudArmorError("CLOUDARMOR_PROJECT is not set")
        backends = [b.strip() for b in os.environ.get("CLOUDARMOR_BACKEND_SERVICES", "").split(",") if b.strip()]
        region = os.environ.get("CLOUDARMOR_HOME_REGION", "").strip() or None
        return cls(project=project, backend_services=backends, home_region=region)


def _quote(value: str) -> str:
    """Quote a value for the Cloud Logging filter language.

    Values come from the operator's own environment, not from untrusted
    input, but quoting keeps hyphens/dots in service names unambiguous.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def start_time(since_hours: float, now: datetime | None = None) -> str:
    """RFC3339 UTC timestamp for the start of the query window."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=since_hours)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_filter(
    kind: str,
    since_hours: float,
    backend_services: list[str],
    region_code: str | None = None,
    now: datetime | None = None,
) -> str:
    """Build a Cloud Logging filter for Cloud Armor DENY entries.

    kind: "enforced" (enforcedSecurityPolicy.outcome=DENY) or
          "preview" (previewSecurityPolicy.configuredAction=DENY).
    region_code: optionally restrict to requests whose source IP geolocates
          to this ISO region code (e.g. "JP") — the false-positive lens.
    """
    parts = ['resource.type="http_load_balancer"']
    if kind == "enforced":
        parts.append('jsonPayload.enforcedSecurityPolicy.outcome="DENY"')
    elif kind == "preview":
        parts.append('jsonPayload.previewSecurityPolicy.configuredAction="DENY"')
    else:
        raise CloudArmorError(f"unknown filter kind: {kind!r}")
    if region_code:
        parts.append("jsonPayload.securityPolicyRequestData.remoteIpInfo.regionCode=" + _quote(region_code))
    if backend_services:
        if len(backend_services) == 1:
            parts.append(f"resource.labels.backend_service_name={_quote(backend_services[0])}")
        else:
            joined = " OR ".join(_quote(b) for b in backend_services)
            parts.append(f"resource.labels.backend_service_name=({joined})")
    parts.append(f'timestamp >= "{start_time(since_hours, now)}"')
    return " ".join(parts)


@dataclass
class DenyEntry:
    """The fields of one DENY log entry that the tools report on."""

    priority: str
    remote_ip: str
    request_url: str
    outcome_kind: str  # "enforced" or "preview"


def _normalize_priority(raw) -> str:
    """Rule priorities arrive as JSON numbers (floats) from Cloud Logging.

    "101.0" would break label lookup and known-normal matching against the
    integer strings operators naturally write in the rules INI, so integral
    floats are folded back to their integer form.
    """
    if isinstance(raw, float) and raw.is_integer():
        return str(int(raw))
    return str(raw)


def _entry_to_deny(entry, kind: str) -> DenyEntry:
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    policy_key = "enforcedSecurityPolicy" if kind == "enforced" else "previewSecurityPolicy"
    priority = _normalize_priority(payload.get(policy_key, {}).get("priority", "?"))
    http = entry.http_request or {}
    return DenyEntry(
        priority=priority,
        remote_ip=str(http.get("remoteIp", "?")),
        request_url=str(http.get("requestUrl", "?")),
        outcome_kind=kind,
    )


class LogClient:
    """Thin wrapper over google-cloud-logging list_entries."""

    def __init__(self, project: str):
        try:
            from google.cloud import logging as gcl
        except ImportError as e:  # pragma: no cover - import guard
            raise CloudArmorError("google-cloud-logging is not installed (pip install cloudarmor-mcp)") from e
        try:
            self._client = gcl.Client(project=project)
        except Exception as e:
            raise CloudArmorError(f"failed to create Cloud Logging client: {e}") from e
        self._descending = gcl.DESCENDING
        self.project = project

    def deny_entries(self, filter_str: str, kind: str, max_entries: int) -> Iterator[DenyEntry]:
        """Yield up to max_entries DenyEntry rows for the filter, newest first."""
        try:
            it = self._client.list_entries(
                filter_=filter_str,
                order_by=self._descending,
                page_size=min(max_entries, 1000),
                max_results=max_entries,
            )
            for entry in it:
                yield _entry_to_deny(entry, kind)
        except CloudArmorError:
            raise
        except Exception as e:
            raise CloudArmorError(f"Cloud Logging query failed: {e}") from e
