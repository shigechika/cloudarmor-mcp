"""Tests for filter building and configuration."""

from datetime import datetime, timezone

import pytest

from cloudarmor_mcp.client import CloudArmorError, Config, build_filter, start_time

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)


def test_start_time_subtracts_window():
    assert start_time(24, now=NOW) == "2026-08-05T12:00:00Z"


def test_build_filter_enforced_single_backend():
    f = build_filter("enforced", 26, ["web-backend"], now=NOW)
    assert 'resource.type="http_load_balancer"' in f
    assert 'jsonPayload.enforcedSecurityPolicy.outcome="DENY"' in f
    assert 'resource.labels.backend_service_name="web-backend"' in f
    assert 'timestamp >= "2026-08-05T10:00:00Z"' in f
    assert "previewSecurityPolicy" not in f


def test_build_filter_preview():
    f = build_filter("preview", 1, [], now=NOW)
    assert 'jsonPayload.previewSecurityPolicy.configuredAction="DENY"' in f
    assert "enforcedSecurityPolicy" not in f
    assert "backend_service_name" not in f


def test_build_filter_region_code():
    f = build_filter("enforced", 1, [], region_code="JP", now=NOW)
    assert 'jsonPayload.securityPolicyRequestData.remoteIpInfo.regionCode="JP"' in f


def test_build_filter_multiple_backends_or_group():
    f = build_filter("enforced", 1, ["b-one", "b-two"], now=NOW)
    assert 'resource.labels.backend_service_name=("b-one" OR "b-two")' in f


def test_build_filter_unknown_kind():
    with pytest.raises(CloudArmorError):
        build_filter("nope", 1, [])


def test_config_from_env_requires_project(monkeypatch):
    monkeypatch.delenv("CLOUDARMOR_PROJECT", raising=False)
    with pytest.raises(CloudArmorError):
        Config.from_env()


def test_config_from_env_parses_lists(monkeypatch):
    monkeypatch.setenv("CLOUDARMOR_PROJECT", "proj")
    monkeypatch.setenv("CLOUDARMOR_BACKEND_SERVICES", "a, b ,")
    monkeypatch.setenv("CLOUDARMOR_HOME_REGION", "JP")
    cfg = Config.from_env()
    assert cfg.project == "proj"
    assert cfg.backend_services == ["a", "b"]
    assert cfg.home_region == "JP"


def test_config_from_env_defaults(monkeypatch):
    monkeypatch.setenv("CLOUDARMOR_PROJECT", "proj")
    monkeypatch.delenv("CLOUDARMOR_BACKEND_SERVICES", raising=False)
    monkeypatch.delenv("CLOUDARMOR_HOME_REGION", raising=False)
    cfg = Config.from_env()
    assert cfg.backend_services == []
    assert cfg.home_region is None


class _FakeEntry:
    def __init__(self, payload, http_request=None):
        self.payload = payload
        self.http_request = http_request


def test_entry_to_deny_normalizes_float_priority():
    from cloudarmor_mcp.client import _entry_to_deny

    entry = _FakeEntry(
        {"enforcedSecurityPolicy": {"priority": 101.0}},
        {"remoteIp": "203.0.113.9", "requestUrl": "https://example.org/"},
    )
    deny = _entry_to_deny(entry, "enforced")
    assert deny.priority == "101"
    assert deny.remote_ip == "203.0.113.9"


def test_entry_to_deny_keeps_int_and_missing():
    from cloudarmor_mcp.client import _entry_to_deny

    assert _entry_to_deny(_FakeEntry({"enforcedSecurityPolicy": {"priority": 42}}), "enforced").priority == "42"
    assert _entry_to_deny(_FakeEntry({}), "enforced").priority == "?"
    assert _entry_to_deny(_FakeEntry(None, None), "preview").priority == "?"
