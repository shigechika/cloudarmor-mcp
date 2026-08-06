"""Tests for tool output shapes with a fake log client (no network)."""

import pytest

import cloudarmor_mcp.server as server
from cloudarmor_mcp.client import DenyEntry


class FakeClient:
    """Returns canned entries; records the filters it was asked for."""

    def __init__(self, entries_by_kind):
        self.entries_by_kind = entries_by_kind
        self.filters = []

    def deny_entries(self, filter_str, kind, max_entries):
        self.filters.append(filter_str)
        yield from self.entries_by_kind.get(kind, [])[:max_entries]


def _deny(priority, ip="203.0.113.1", url="https://example.org/x", kind="enforced"):
    return DenyEntry(priority=priority, remote_ip=ip, request_url=url, outcome_kind=kind)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("CLOUDARMOR_PROJECT", "proj")
    monkeypatch.setenv("CLOUDARMOR_BACKEND_SERVICES", "web-backend")
    monkeypatch.setenv("CLOUDARMOR_HOME_REGION", "JP")
    monkeypatch.delenv("CLOUDARMOR_RULES_INI", raising=False)
    server.reset_client()
    yield
    server.reset_client()


def _install(monkeypatch, fake):
    monkeypatch.setattr(server, "_client", lambda: fake)


def test_enforce_denies_aggregates_by_priority(env, monkeypatch):
    fake = FakeClient({"enforced": [_deny("101"), _deny("101"), _deny("500")]})
    _install(monkeypatch, fake)
    out = server.enforce_denies(since_hours=24)
    assert "Enforced DENY, last 24h: 3" in out
    assert "rule 101: 2" in out
    assert "rule 500: 1" in out


def test_preview_denies_empty(env, monkeypatch):
    fake = FakeClient({})
    _install(monkeypatch, fake)
    out = server.preview_denies(since_hours=24)
    assert "Preview DENY, last 24h: 0" in out


def test_home_region_denies_flags_suspicious(env, monkeypatch, tmp_path):
    rules = tmp_path / "rules.ini"
    rules.write_text("[rules]\n500 = AutoDiscover\n[home]\nknown_normal_priorities = 500\n")
    monkeypatch.setenv("CLOUDARMOR_RULES_INI", str(rules))
    fake = FakeClient({"enforced": [_deny("500"), _deny("500"), _deny("1002", ip="198.51.100.7")]})
    _install(monkeypatch, fake)
    out = server.home_region_denies(since_hours=24)
    assert "known-normal priorities: 2 (suppressed)" in out
    assert "rule 1002" in out
    assert "198.51.100.7" in out
    # region filter actually reached the query
    assert any('regionCode="JP"' in f for f in fake.filters)


def test_home_region_denies_without_region(env, monkeypatch):
    monkeypatch.delenv("CLOUDARMOR_HOME_REGION")
    fake = FakeClient({})
    _install(monkeypatch, fake)
    out = server.home_region_denies(since_hours=24)
    assert "not set" in out


def test_home_region_denies_all_normal(env, monkeypatch, tmp_path):
    rules = tmp_path / "rules.ini"
    rules.write_text("[home]\nknown_normal_priorities = 500\n")
    monkeypatch.setenv("CLOUDARMOR_RULES_INI", str(rules))
    fake = FakeClient({"enforced": [_deny("500")]})
    _install(monkeypatch, fake)
    out = server.home_region_denies(since_hours=24)
    assert "no suspicious home-region denies" in out


def test_daily_brief_contains_all_sections(env, monkeypatch):
    fake = FakeClient(
        {
            "enforced": [_deny("101"), _deny("500")],
            "preview": [_deny("1010", kind="preview")],
        }
    )
    _install(monkeypatch, fake)
    out = server.daily_brief(since_hours=26)
    assert "# Cloud Armor brief — project proj, last 26h" in out
    assert "## Enforced DENY: 2" in out
    assert "## JP-sourced DENY" in out
    assert "## Preview DENY: 1" in out


def test_daily_brief_rule_labels(env, monkeypatch, tmp_path):
    rules = tmp_path / "rules.ini"
    rules.write_text("[rules]\n101 = deep-path crawler block\n")
    monkeypatch.setenv("CLOUDARMOR_RULES_INI", str(rules))
    fake = FakeClient({"enforced": [_deny("101")]})
    _install(monkeypatch, fake)
    out = server.daily_brief(since_hours=26)
    assert "rule 101 (deep-path crawler block): 1" in out


def test_capped_count_is_flagged(env, monkeypatch):
    monkeypatch.setenv("CLOUDARMOR_MAX_ENTRIES", "5")
    entries = [_deny("101") for _ in range(10)]
    fake = FakeClient({"enforced": entries})
    _install(monkeypatch, fake)
    out = server.enforce_denies(since_hours=24)
    assert ">= 5 (capped at 5)" in out


def test_max_entries_env_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("CLOUDARMOR_MAX_ENTRIES", "not-a-number")
    assert server._max_entries() == server.DEFAULT_MAX_ENTRIES


def test_health_check_shape_without_project(monkeypatch):
    monkeypatch.delenv("CLOUDARMOR_PROJECT", raising=False)
    server.reset_client()
    result = server.health_check()
    assert result["status"] == "error"
    assert result["service"] == "cloudarmor-mcp"
    assert set(result) == {
        "status",
        "service",
        "version",
        "project",
        "backend_services",
        "home_region",
        "rules_ini",
        "probe",
    }


def test_health_check_healthy_with_fake(env, monkeypatch):
    fake = FakeClient({"enforced": []})
    _install(monkeypatch, fake)
    result = server.health_check()
    assert result["status"] == "healthy"
    assert result["probe"] == "ok"
    assert result["project"] == "proj"
