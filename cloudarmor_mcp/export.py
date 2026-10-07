"""One-day, per-entry exports of load-balancer log entries.

`deny-export` writes every Cloud Armor DENY entry of a day; `traffic-export`
writes a sampled subset of all requests of a day (allowed, denied and
cache-served alike). This is the single place in the package that writes
per-entry log data — source IP, host, path, User-Agent — and it writes to
stdout only, for an operator batch that runs on the same host and
aggregates the day itself. The MCP tools stay aggregate-only (see
REVIEW.md). Query-string contents, cookies and headers other than
User-Agent are never emitted.
"""

import json
import re
import sys
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cloudarmor_mcp import __version__
from cloudarmor_mcp.client import (
    CloudArmorError,
    LogClient,
    _normalize_priority,
    _rfc3339,
    build_sample_filter,
    build_window_filter,
    validate_sample,
)

EXPORT_SCHEMA = "cloudarmor-mcp/deny-export/1"
TRAFFIC_SCHEMA = "cloudarmor-mcp/traffic-export/1"
DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_SAMPLE = 0.01
UA_MAX = 200
PATH_MAX = 2048
KINDS = ("both", "enforced", "preview")
RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ExportConfigError(Exception):
    """Bad date, time zone, window or option — the caller exits 2."""


def day_window(date: str, tz: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    """[00:00, 24:00) of the calendar day in tz, as aware datetimes.

    The day must have ended: an export of a running day would be silently
    incomplete, and the consumer treats every export as the whole day.
    """
    if not RE_DATE.match(date or ""):
        raise ExportConfigError(f"--date must be YYYY-MM-DD, got {date!r}")
    try:
        d = datetime.strptime(date, "%Y-%m-%d").date()
    except ValueError as e:
        raise ExportConfigError(f"--date must be YYYY-MM-DD, got {date!r}") from e
    try:
        zone = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError, TypeError) as e:
        raise ExportConfigError(f"unknown time zone {tz!r}") from e
    start = datetime(d.year, d.month, d.day, tzinfo=zone)
    end = datetime.combine(d + timedelta(days=1), datetime.min.time(), tzinfo=zone)
    now = now or datetime.now(timezone.utc)
    if end > now:
        raise ExportConfigError(f"{date} has not ended yet in {tz}")
    return start, end


def _policy(section) -> dict | None:
    if not isinstance(section, dict) or not section:
        return None
    ids = section.get("preconfiguredExprIds")
    return {
        "policy": section.get("name"),
        "priority": _normalize_priority(section.get("priority", "?")),
        "action": section.get("configuredAction"),
        "outcome": section.get("outcome"),
        "rule_ids": [str(x) for x in ids] if isinstance(ids, list) else [],
    }


def _int_or_none(v):
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return None


def entry_to_record(entry) -> dict:
    """Flatten one SDK log entry. Never raises: odd shapes become None fields."""
    payload = entry.payload if isinstance(entry.payload, dict) else {}
    http = entry.http_request if isinstance(entry.http_request, dict) else {}
    partial = not isinstance(entry.payload, dict) or not isinstance(entry.http_request, dict)
    labels = getattr(getattr(entry, "resource", None), "labels", None)
    labels = labels if isinstance(labels, dict) else {}
    ip_info = payload.get("securityPolicyRequestData")
    ip_info = ip_info.get("remoteIpInfo") if isinstance(ip_info, dict) else None
    ip_info = ip_info if isinstance(ip_info, dict) else {}
    url = str(http.get("requestUrl") or "")
    try:
        parts = urlsplit(url)
        host = parts.hostname  # lower-cased, brackets and port removed
        path = parts.path
        query_len = len(parts.query)
    except ValueError:
        host, path, query_len, partial = None, None, 0, True
    if host:
        host = host.rstrip(".")
    ts = getattr(entry, "timestamp", None)
    ua = http.get("userAgent")
    return {
        "id": getattr(entry, "insert_id", None),
        "ts": ts.astimezone(timezone.utc).isoformat() if isinstance(ts, datetime) else None,
        "enforced": _policy(payload.get("enforcedSecurityPolicy")),
        "preview": _policy(payload.get("previewSecurityPolicy")),
        "status_details": payload.get("statusDetails"),
        "ip": str(http["remoteIp"]) if http.get("remoteIp") else None,
        "region": ip_info.get("regionCode") or None,
        "asn": _int_or_none(ip_info.get("asn")),
        "method": http.get("requestMethod"),
        "host": host or None,
        "path": (path[:PATH_MAX] if path else None),
        "path_truncated": bool(path) and len(path) > PATH_MAX,
        "query_len": query_len,
        "status": _int_or_none(http.get("status")),
        "cache_hit": http.get("cacheHit") is True,
        "ua": str(ua)[:UA_MAX] if ua else None,
        "backend": labels.get("backend_service_name"),
        "partial": partial,
    }


def run_export(
    *,
    project: str,
    backend_services: list[str],
    date: str,
    tz: str,
    kind: str,
    max_entries: int,
    out,
    client_factory: Callable[[str], LogClient] | None = None,
    client: LogClient | None = None,
    now: datetime | None = None,
) -> int:
    """Write one day of DENY entries as a JSON document to `out`; return the records written.

    Pass `client` to separate client-creation (configuration) errors from
    query errors.
    """
    if kind not in KINDS:
        raise ExportConfigError(f"--kind must be one of {', '.join(KINDS)}")
    if max_entries < 1:
        raise ExportConfigError("--max-entries must be at least 1")
    start, end = day_window(date, tz, now)
    filter_str = build_window_filter(kind, backend_services, start, end)
    header = _header(EXPORT_SCHEMA, project, backend_services, date, tz, start, end, max_entries)
    header["kind"] = kind
    return _write(header, filter_str, client or (client_factory or LogClient)(project), max_entries, out)


def check_sample(sample) -> None:
    """Reject a sample rate outside [MIN_SAMPLE, 1] (or a bool) before any query is made."""
    try:
        validate_sample(sample)
    except CloudArmorError as e:
        raise ExportConfigError(str(e).replace("sample rate", "--sample", 1)) from e


def run_traffic_export(
    *,
    project: str,
    backend_services: list[str],
    date: str,
    tz: str,
    sample: float,
    max_entries: int,
    out,
    client_factory: Callable[[str], LogClient] | None = None,
    client: LogClient | None = None,
    now: datetime | None = None,
) -> int:
    """Write a sampled day of all load-balancer requests as a JSON document to `out`.

    The subset comes from Cloud Logging's sample(insertId, rate), so it is
    spread evenly over the day and stable across runs. Scale counts by
    1 / `sample` to estimate the day — but not when `capped` is true: entries
    are read oldest first, so a capped export is the early part of the day
    only. Records have the same shape as deny-export's; `enforced` is null
    when no backend security policy evaluated the request (a CDN cache hit,
    for example).
    """
    check_sample(sample)
    if max_entries < 1:
        raise ExportConfigError("--max-entries must be at least 1")
    start, end = day_window(date, tz, now)
    filter_str = build_sample_filter(backend_services, start, end, sample)
    header = _header(TRAFFIC_SCHEMA, project, backend_services, date, tz, start, end, max_entries)
    header["sample"] = sample
    return _write(header, filter_str, client or (client_factory or LogClient)(project), max_entries, out)


def _header(schema, project, backend_services, date, tz, start, end, max_entries) -> dict:
    return {
        "schema": schema,
        "version": __version__,
        "project": project,
        "backend_services": backend_services,
        "date": date,
        "tz": tz,
        "window": {"start": _rfc3339(start), "end": _rfc3339(end)},
        "max_entries": max_entries,
        "order": "asc",
    }


def _write(header: dict, filter_str: str, client: LogClient, max_entries: int, out) -> int:
    """Stream the entries matching filter_str as one JSON document; return the records written.

    The first entry is fetched before anything is written so that auth or
    filter errors leave stdout empty. Records are written one per line, so
    memory does not grow with the day. `capped` is decided by asking for one
    entry more than the cap; an export with exactly max_entries entries is
    complete.
    """
    entries: Iterator = client.raw_entries(filter_str, max_entries + 1, ascending=True)
    first = next(entries, None)
    head = json.dumps(header, ensure_ascii=False)
    out.write(head[:-1] + ', "entries": [\n')
    count = fetched = malformed = 0
    capped = False

    def emit(entry):
        nonlocal count, fetched, malformed, capped
        fetched += 1
        if fetched > max_entries:
            capped = True
            return False
        try:
            rec = entry_to_record(entry)
        except Exception:  # a record must never abort the day; it is counted instead
            malformed += 1
            return True
        out.write(("" if count == 0 else ",\n") + json.dumps(rec, ensure_ascii=False))
        count += 1
        return True

    if first is not None and emit(first):
        for entry in entries:
            if not emit(entry):
                break
    trailer = {
        "count": count,
        "fetched": min(fetched, max_entries),
        "malformed": malformed,
        "capped": capped,
        "filter": filter_str,
    }
    out.write("\n], " + json.dumps(trailer, ensure_ascii=False)[1:] + "\n")
    out.flush()
    return count


def utf8_stdout():
    """A UTF-8 text stream over sys.stdout regardless of the locale."""
    import io

    return io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n", write_through=True)
