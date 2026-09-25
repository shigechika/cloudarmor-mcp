"""Cloud Logging queries for Cloud Armor (http_load_balancer) log entries.

The Google client library is imported lazily so unit tests can exercise
filter building and aggregation without the dependency installed or any
network access.
"""

import itertools
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Minimum seconds between two entries.list pages in raw_entries: 60 requests/minute is the default quota.
PAGE_INTERVAL = 1.2
PAGE_SIZE = 1000  # entries.list page_size for deny-export


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


def _filter_parts(kind: str, backend_services: list[str], region_code: str | None = None) -> list[str]:
    """The filter clauses shared by the relative-window and fixed-window filters."""
    parts = ['resource.type="http_load_balancer"']
    if kind == "enforced":
        parts.append('jsonPayload.enforcedSecurityPolicy.outcome="DENY"')
    elif kind == "preview":
        parts.append('jsonPayload.previewSecurityPolicy.configuredAction="DENY"')
    elif kind == "both":
        parts.append(
            '(jsonPayload.enforcedSecurityPolicy.outcome="DENY"'
            ' OR jsonPayload.previewSecurityPolicy.configuredAction="DENY")'
        )
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
    return parts


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
    parts = _filter_parts(kind, backend_services, region_code)
    parts.append(f'timestamp >= "{start_time(since_hours, now)}"')
    return " ".join(parts)


def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_window_filter(kind: str, backend_services: list[str], start: datetime, end: datetime) -> str:
    """Filter for the half-open window [start, end) — used by deny-export.

    kind may also be "both": entries where either policy reports DENY.
    """
    if end <= start:
        raise CloudArmorError("window end must be after its start")
    parts = _filter_parts(kind, backend_services)
    parts.append(f'timestamp >= "{_rfc3339(start)}"')
    parts.append(f'timestamp < "{_rfc3339(end)}"')
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
        self._ascending = gcl.ASCENDING
        self.project = project

    def _list_pages(self, filter_str: str, order_by: str, page_size: int) -> Iterator[tuple[list, bool]]:
        """Yield (SDK LogEntry objects, more pages follow) per entries.list response.

        Mirrors google-cloud-logging's own list_entries (3.x) but keeps the
        gRPC pager's page boundaries, so each item is exactly one request,
        empty pages included. The filter must carry its own timestamp bound:
        the SDK's default of "last 24 hours" is not added here. With the HTTP
        transport (GOOGLE_CLOUD_DISABLE_GRPC) there is no pager, so the SDK
        generator is cut into page_size chunks instead (pacing is then best
        effort: short pages are not visible).
        """
        api = self._client.logging_api
        gapic = getattr(api, "_gapic_api", None)
        if gapic is None:
            it = iter(
                self._client.list_entries(filter_=filter_str, order_by=order_by, page_size=page_size, max_results=None)
            )
            while True:
                chunk = list(itertools.islice(it, page_size))
                yield chunk, len(chunk) == page_size
                if len(chunk) < page_size:
                    return

        from google.cloud.logging_v2._gapic import _parse_log_entry
        from google.cloud.logging_v2._helpers import entry_from_resource
        from google.cloud.logging_v2.types import ListLogEntriesRequest
        from google.cloud.logging_v2.types import LogEntry as LogEntryPB

        request = ListLogEntriesRequest(
            resource_names=[f"projects/{self.project}"],
            filter=filter_str,
            order_by=order_by,
            page_size=page_size,
        )
        pager = gapic.list_log_entries(request=request)
        loggers: dict = {}
        for page in pager.pages:
            entries = [
                entry_from_resource(_parse_log_entry(LogEntryPB.pb(e)), self._client, loggers=loggers)
                for e in page.entries
            ]
            yield entries, bool(page.next_page_token)

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

    def raw_entries(
        self, filter_str: str, max_entries: int, ascending: bool = False, page_interval: float = PAGE_INTERVAL
    ) -> Iterator:
        """Yield up to max_entries SDK log entries unchanged (deny-export uses this).

        Oldest first when ascending, so a capped export is a contiguous prefix of
        the window. Pages are fetched at most one per page_interval seconds so a
        big day stays under the entries.list quota (60 requests per minute per
        project); a quota error (429) before the first entry is retried once.

        Pages are walked one API response at a time (see _list_pages) because
        the SDK's list_entries() generator hides page boundaries: short or empty
        pages that still carry a next-page token would otherwise be fetched
        back to back inside a single pull.
        """
        page_size = min(max_entries, PAGE_SIZE)
        order_by = self._ascending if ascending else self._descending
        for attempt in (1, 2):
            yielded = False
            try:
                pages = self._list_pages(filter_str, order_by, page_size)
                n = 0
                last = None
                while n < max_entries:
                    if last is not None:
                        # every pull after the first sends one entries.list request
                        wait = page_interval - (time.monotonic() - last)
                        if wait > 0:
                            time.sleep(wait)
                    last = time.monotonic()
                    item = next(pages, None)
                    if item is None:
                        return
                    page, more = item
                    for entry in page:
                        if n >= max_entries:
                            return
                        n += 1
                        yielded = True
                        yield entry
                    if not more:
                        return
                return
            except Exception as e:
                if attempt == 1 and not yielded and type(e).__name__ in ("ResourceExhausted", "TooManyRequests"):
                    time.sleep(15)
                    continue
                raise CloudArmorError(f"Cloud Logging query failed: {e}") from e
