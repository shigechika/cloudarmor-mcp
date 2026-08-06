"""Cloud Armor WAF patrol MCP Server — tools."""

import configparser
import os
from collections import Counter

from mcp.server.fastmcp import FastMCP

from cloudarmor_mcp.client import CloudArmorError, Config, LogClient, build_filter
from cloudarmor_mcp.rules import Rules, load_rules

mcp = FastMCP("cloudarmor-mcp")

# Hard cap on entries fetched per query (CLOUDARMOR_MAX_ENTRIES overrides).
# When the cap is hit the report says ">= N (capped)" instead of pretending
# the count is exact — silent truncation must never read as "covered
# everything".
DEFAULT_MAX_ENTRIES = 2000


def _max_entries() -> int:
    try:
        return max(1, int(os.environ.get("CLOUDARMOR_MAX_ENTRIES", DEFAULT_MAX_ENTRIES)))
    except ValueError:
        return DEFAULT_MAX_ENTRIES


# How many home-region DENY detail lines to show before folding to a count.
HOME_DETAIL_LIMIT = 40

# Default patrol window (hours). 26 h keeps a daily patrol overlapping
# yesterday's run instead of leaving a gap when start times drift.
DEFAULT_SINCE_HOURS = 26.0

# Cached client: a stdio server is long-lived and single-user, so build the
# authenticated client once and reuse its connection pool across calls.
_CLIENT: LogClient | None = None


def _client() -> LogClient:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = LogClient(Config.from_env().project)
    return _CLIENT


def reset_client() -> None:
    """Drop the cached client so the next call rebuilds it."""
    global _CLIENT
    _CLIENT = None


def _load_rules_safe() -> tuple[Rules, str | None]:
    try:
        return load_rules(), None
    except (configparser.Error, OSError, UnicodeDecodeError) as e:
        return Rules(), f"rules INI could not be read: {e}"


def _count_fragment(shown: int, cap: int) -> str:
    return f">= {shown} (capped at {cap})" if shown >= cap else str(shown)


def _priority_table(counts: Counter, rules: Rules) -> list[str]:
    lines = []
    for priority, n in counts.most_common():
        lines.append(f"  rule {priority}{rules.label(priority)}: {n}")
    return lines


def _collect(kind: str, since_hours: float, region_code: str | None = None) -> tuple[list, int]:
    """Fetch entries for the window; returns (entries, cap) so reports can flag capping."""
    cfg = Config.from_env()
    cap = _max_entries()
    filter_str = build_filter(kind, since_hours, cfg.backend_services, region_code)
    return list(_client().deny_entries(filter_str, kind, cap)), cap


@mcp.tool()
def health_check() -> dict:
    """Service health: version, config presence and a minimal API probe.

    Returns a fixed shape (status/service/version + backend fields) so a
    monitoring caller never has to branch on missing keys. status is
    "healthy" when the config loads and a 1-entry probe query succeeds,
    "degraded" when config loads but the probe fails, "error" when the
    config itself is unusable.
    """
    from cloudarmor_mcp import __version__

    result = {
        "status": "error",
        "service": "cloudarmor-mcp",
        "version": __version__,
        "project": None,
        "backend_services": [],
        "home_region": None,
        "rules_ini": False,
        "probe": None,
    }
    try:
        cfg = Config.from_env()
    except CloudArmorError as e:
        result["probe"] = str(e)
        return result
    result["project"] = cfg.project
    result["backend_services"] = cfg.backend_services
    result["home_region"] = cfg.home_region
    rules, rules_err = _load_rules_safe()
    result["rules_ini"] = bool(rules.labels or rules.known_normal)
    try:
        filter_str = build_filter("enforced", 0.1, cfg.backend_services)
        list(_client().deny_entries(filter_str, "enforced", 1))
        result["status"] = "healthy"
        result["probe"] = "ok"
    except CloudArmorError as e:
        result["status"] = "degraded"
        result["probe"] = str(e)
    if rules_err:
        result["probe"] = f"{result['probe']}; {rules_err}"
    return result


@mcp.tool()
def enforce_denies(since_hours: float = DEFAULT_SINCE_HOURS) -> str:
    """Enforced DENY counts per Cloud Armor rule priority over the window."""
    rules, rules_err = _load_rules_safe()
    entries, cap = _collect("enforced", since_hours)
    counts = Counter(e.priority for e in entries)
    lines = [f"Enforced DENY, last {since_hours:g}h: {_count_fragment(len(entries), cap)}"]
    lines += _priority_table(counts, rules)
    if rules_err:
        lines.append(f"  [warn] {rules_err}")
    return "\n".join(lines)


@mcp.tool()
def preview_denies(since_hours: float = DEFAULT_SINCE_HOURS) -> str:
    """Preview (dry-run) DENY counts per rule priority over the window.

    A preview rule that stays free of false positives is a candidate for
    promotion to enforce.
    """
    rules, rules_err = _load_rules_safe()
    entries, cap = _collect("preview", since_hours)
    counts = Counter(e.priority for e in entries)
    lines = [f"Preview DENY, last {since_hours:g}h: {_count_fragment(len(entries), cap)}"]
    lines += _priority_table(counts, rules)
    if rules_err:
        lines.append(f"  [warn] {rules_err}")
    return "\n".join(lines)


@mcp.tool()
def home_region_denies(since_hours: float = DEFAULT_SINCE_HOURS) -> str:
    """Enforced DENYs whose source IP geolocates to the home region.

    This is the false-positive lens: home-region users being denied on a
    priority that is not marked known-normal deserves review. Requires
    CLOUDARMOR_HOME_REGION.
    """
    cfg = Config.from_env()
    if not cfg.home_region:
        return "CLOUDARMOR_HOME_REGION is not set — home-region check skipped."
    rules, rules_err = _load_rules_safe()
    entries, cap = _collect("enforced", since_hours, region_code=cfg.home_region)
    lines = [
        f"Enforced DENY from region {cfg.home_region}, last {since_hours:g}h: {_count_fragment(len(entries), cap)}"
    ]
    suspicious = [e for e in entries if not rules.is_known_normal(e.priority)]
    normal = len(entries) - len(suspicious)
    if normal:
        lines.append(f"  known-normal priorities: {normal} (suppressed)")
    for e in suspicious[:HOME_DETAIL_LIMIT]:
        lines.append(f"  rule {e.priority}{rules.label(e.priority)}  {e.remote_ip}  {e.request_url}")
    if len(suspicious) > HOME_DETAIL_LIMIT:
        lines.append(f"  ... and {len(suspicious) - HOME_DETAIL_LIMIT} more")
    if not suspicious:
        lines.append("  no suspicious home-region denies — WAF looks clean")
    if rules_err:
        lines.append(f"  [warn] {rules_err}")
    return "\n".join(lines)


def _daily_brief_text(since_hours: float) -> tuple[str, bool]:
    """Build the brief; returns (text, had_error)."""
    cfg = Config.from_env()
    rules, rules_err = _load_rules_safe()
    sections: list[str] = [f"# Cloud Armor brief — project {cfg.project}, last {since_hours:g}h"]
    had_error = False

    try:
        enforced, cap = _collect("enforced", since_hours)
        counts = Counter(e.priority for e in enforced)
        sections.append(f"## Enforced DENY: {_count_fragment(len(enforced), cap)}")
        sections += _priority_table(counts, rules)
    except CloudArmorError as e:
        sections.append(f"## Enforced DENY: query failed — {e}")
        had_error = True

    if cfg.home_region:
        try:
            home, cap = _collect("enforced", since_hours, region_code=cfg.home_region)
            suspicious = [e for e in home if not rules.is_known_normal(e.priority)]
            sections.append(
                f"## {cfg.home_region}-sourced DENY (false-positive lens): "
                f"{_count_fragment(len(home), cap)}, suspicious {len(suspicious)}"
            )
            for e in suspicious[:HOME_DETAIL_LIMIT]:
                sections.append(f"  rule {e.priority}{rules.label(e.priority)}  {e.remote_ip}  {e.request_url}")
            if len(suspicious) > HOME_DETAIL_LIMIT:
                sections.append(f"  ... and {len(suspicious) - HOME_DETAIL_LIMIT} more")
            if not suspicious:
                sections.append("  none outside known-normal priorities")
        except CloudArmorError as e:
            sections.append(f"## {cfg.home_region}-sourced DENY: query failed — {e}")
            had_error = True

    try:
        preview, cap = _collect("preview", since_hours)
        counts = Counter(e.priority for e in preview)
        sections.append(f"## Preview DENY: {_count_fragment(len(preview), cap)}")
        sections += _priority_table(counts, rules)
    except CloudArmorError as e:
        sections.append(f"## Preview DENY: query failed — {e}")
        had_error = True

    if rules_err:
        sections.append(f"[warn] {rules_err}")
    return "\n".join(sections), had_error


@mcp.tool()
def daily_brief(since_hours: float = DEFAULT_SINCE_HOURS) -> str:
    """Morning patrol summary: enforced DENYs by rule, home-region

    false-positive check, and preview DENYs, in one call.
    """
    text, _ = _daily_brief_text(since_hours)
    return text
