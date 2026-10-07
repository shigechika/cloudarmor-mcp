"""Tests for the deny-export subcommand's window, record extraction and streaming output."""

import io
import json
from collections import namedtuple
from datetime import datetime, timezone

import pytest

from cloudarmor_mcp import export
from cloudarmor_mcp.client import CloudArmorError, build_sample_filter, build_window_filter

NOW = datetime(2026, 9, 24, 3, 0, 0, tzinfo=timezone.utc)
Resource = namedtuple("Resource", "labels")


class FakeEntry:
    def __init__(self, payload, http_request=None, *, ts=None, insert_id="e1", labels=None):
        self.payload = payload
        self.http_request = http_request
        self.timestamp = ts
        self.insert_id = insert_id
        self.resource = Resource(labels if labels is not None else {"backend_service_name": "web-backend"})


class FakeClient:
    def __init__(self, entries, fail=None):
        self.entries = entries
        self.fail = fail
        self.calls = []

    def raw_entries(self, filter_str, max_entries, ascending=False):
        self.calls.append((filter_str, max_entries, ascending))
        if self.fail:
            raise self.fail
        yield from self.entries[:max_entries]


def _deny(priority=4242.0, ip="198.51.100.7", url="https://www.example.org/index.php?x=1", preview=None, **kw):
    payload = {
        "enforcedSecurityPolicy": {
            "name": "example-policy",
            "priority": priority,
            "configuredAction": "DENY",
            "outcome": "DENY",
            "preconfiguredExprIds": ["owasp-crs-v030301-id930130-lfi"],
        },
        "securityPolicyRequestData": {"remoteIpInfo": {"regionCode": "JP", "asn": 64496.0}},
        "statusDetails": "denied_by_security_policy",
    }
    if preview:
        payload["previewSecurityPolicy"] = preview
    http = {"requestMethod": "GET", "requestUrl": url, "remoteIp": ip, "status": 403, "userAgent": "curl/8"}
    return FakeEntry(
        payload,
        http,
        ts=kw.get("ts", datetime(2026, 9, 23, 1, 2, 3, tzinfo=timezone.utc)),
        **{k: v for k, v in kw.items() if k != "ts"},
    )


def _run(entries, **kw):
    out = io.StringIO()
    fake = FakeClient(entries, fail=kw.pop("fail", None))
    args = dict(
        project="example-prod",
        backend_services=["web-backend"],
        date="2026-09-23",
        tz="Asia/Tokyo",
        kind="both",
        max_entries=100,
        out=out,
        client_factory=lambda p: fake,
        now=NOW,
    )
    args.update(kw)
    n = export.run_export(**args)
    return n, json.loads(out.getvalue()), fake


# --- window -----------------------------------------------------------------


def test_day_window_jst_converts_to_utc():
    start, end = export.day_window("2026-09-23", "Asia/Tokyo", now=NOW)
    assert start.astimezone(timezone.utc).isoformat() == "2026-09-22T15:00:00+00:00"
    assert end.astimezone(timezone.utc).isoformat() == "2026-09-23T15:00:00+00:00"


def test_day_window_dst_transition_day_is_23_hours():
    start, end = export.day_window("2026-03-08", "America/New_York", now=NOW)
    assert (end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds() == 23 * 3600


@pytest.mark.parametrize(
    "date,tz",
    [("2026-09-24", "Asia/Tokyo"), ("2026/09/03", "UTC"), ("2026-9-3", "UTC"), ("2026-09-23", "Mars/Olympus")],
)
def test_day_window_rejects_unfinished_or_bad_input(date, tz):
    with pytest.raises(export.ExportConfigError):
        export.day_window(date, tz, now=NOW)


def test_window_filter_has_both_bounds_and_both_kinds():
    start, end = export.day_window("2026-09-23", "Asia/Tokyo", now=NOW)
    f = build_window_filter("both", ["a", "b"], start, end)
    assert 'timestamp >= "2026-09-22T15:00:00Z"' in f and 'timestamp < "2026-09-23T15:00:00Z"' in f
    assert '(jsonPayload.enforcedSecurityPolicy.outcome="DENY" OR jsonPayload.previewSecurityPolicy' in f
    assert 'backend_service_name=("a" OR "b")' in f
    with pytest.raises(CloudArmorError):
        build_window_filter("enforced", [], end, start)


# --- records ------------------------------------------------------------------


def test_record_enforced_fields():
    rec = export.entry_to_record(_deny())
    assert rec["enforced"] == {
        "policy": "example-policy",
        "priority": "4242",
        "action": "DENY",
        "outcome": "DENY",
        "rule_ids": ["owasp-crs-v030301-id930130-lfi"],
    }
    assert rec["preview"] is None
    assert rec["ip"] == "198.51.100.7" and rec["region"] == "JP" and rec["asn"] == 64496
    assert rec["host"] == "www.example.org" and rec["path"] == "/index.php" and rec["query_len"] == 3
    assert rec["status"] == 403 and rec["ua"] == "curl/8" and rec["backend"] == "web-backend"
    assert rec["ts"] == "2026-09-23T01:02:03+00:00" and rec["id"] == "e1" and rec["partial"] is False


def test_record_preview_and_default_allow_are_both_kept():
    e = _deny(
        priority=2147483647.0,
        preview={"name": "example-policy", "priority": 2424.0, "configuredAction": "DENY", "preconfiguredExprIds": []},
    )
    e.payload["enforcedSecurityPolicy"]["outcome"] = "ACCEPT"
    e.payload["enforcedSecurityPolicy"]["configuredAction"] = "ALLOW"
    rec = export.entry_to_record(e)
    assert rec["enforced"]["priority"] == "2147483647" and rec["enforced"]["outcome"] == "ACCEPT"
    assert rec["preview"]["priority"] == "2424" and rec["preview"]["rule_ids"] == []


def test_record_host_is_lowercased_without_port_or_brackets_and_path_truncated():
    rec = export.entry_to_record(_deny(url="https://[2001:DB8::1]:8443/" + "a" * 3000 + "?q=" + "x" * 50))
    assert rec["host"] == "2001:db8::1"
    assert len(rec["path"]) == export.PATH_MAX and rec["path_truncated"] is True and rec["query_len"] == 52
    rec = export.entry_to_record(_deny(url="https://WWW.Example.org.:443/x"))
    assert rec["host"] == "www.example.org"


def test_record_malformed_never_raises():
    e = FakeEntry(None, None, ts=None, insert_id=None, labels=None)
    rec = export.entry_to_record(e)
    assert rec["enforced"] is None and rec["preview"] is None and rec["ip"] is None and rec["host"] is None
    assert rec["asn"] is None and rec["partial"] is True and rec["ts"] is None
    e = _deny()
    e.payload["securityPolicyRequestData"]["remoteIpInfo"]["asn"] = "x"
    assert export._int_or_none(float("inf")) is None and export._int_or_none("1e400") is None
    e.payload["enforcedSecurityPolicy"]["preconfiguredExprIds"] = "not-a-list"
    e.http_request["userAgent"] = "ü" * 500
    rec = export.entry_to_record(e)
    assert rec["asn"] is None and rec["enforced"]["rule_ids"] == [] and len(rec["ua"]) == export.UA_MAX


# --- run_export ---------------------------------------------------------------


def test_run_export_document_shape_and_asc_query():
    n, doc, fake = _run([_deny(insert_id="a"), _deny(insert_id="b")])
    assert n == 2 and doc["count"] == 2 and doc["fetched"] == 2 and doc["capped"] is False and doc["malformed"] == 0
    assert doc["schema"] == export.EXPORT_SCHEMA and doc["kind"] == "both" and doc["order"] == "asc"
    assert doc["window"] == {"start": "2026-09-22T15:00:00Z", "end": "2026-09-23T15:00:00Z"}
    assert [r["id"] for r in doc["entries"]] == ["a", "b"]
    assert fake.calls[0][1] == 101 and fake.calls[0][2] is True  # cap + 1, ascending


def test_run_export_exactly_at_cap_is_not_capped_but_one_more_is():
    entries = [_deny(insert_id=str(i)) for i in range(5)]
    _, doc, _ = _run(entries, max_entries=5)
    assert doc["count"] == 5 and doc["capped"] is False
    _, doc, _ = _run(entries + [_deny(insert_id="6")], max_entries=5)
    assert doc["count"] == 5 and doc["fetched"] == 5 and doc["capped"] is True


def test_run_export_counts_malformed_without_aborting(monkeypatch):
    calls = {"n": 0}
    real = export.entry_to_record

    def flaky(entry):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real(entry)

    monkeypatch.setattr(export, "entry_to_record", flaky)
    n, doc, _ = _run([_deny(insert_id=str(i)) for i in range(3)])
    assert n == 2 and doc["count"] == 2 and doc["malformed"] == 1 and doc["fetched"] == 3


def test_run_export_empty_day_and_utf8():
    n, doc, _ = _run([])
    assert n == 0 and doc["entries"] == [] and doc["count"] == 0
    e = _deny()
    e.http_request["userAgent"] = "ブラウザ/1.0"
    _, doc, _ = _run([e])
    assert doc["entries"][0]["ua"] == "ブラウザ/1.0"


def test_run_export_query_failure_leaves_stdout_empty():
    out = io.StringIO()
    fake = FakeClient([], fail=CloudArmorError("denied"))
    with pytest.raises(CloudArmorError):
        export.run_export(
            project="p",
            backend_services=[],
            date="2026-09-23",
            tz="UTC",
            kind="enforced",
            max_entries=10,
            out=out,
            client_factory=lambda p: fake,
            now=NOW,
        )
    assert out.getvalue() == ""


@pytest.mark.parametrize("kw", [{"kind": "nope"}, {"max_entries": 0}])
def test_run_export_rejects_bad_options(kw):
    with pytest.raises(export.ExportConfigError):
        _run([], **kw)


def _lc(pages, fetches, fail_first=None):
    """A LogClient whose _list_pages yields the given pages, one request each (empty pages too)."""
    from cloudarmor_mcp.client import LogClient

    calls = {"n": 0}

    def list_pages(filter_str, order_by, page_size):
        calls["n"] += 1
        if fail_first and calls["n"] == 1:
            raise fail_first("quota")
        for i, page in enumerate(pages):
            fetches.append("req")
            yield list(page), i < len(pages) - 1

    lc = LogClient.__new__(LogClient)
    lc._client, lc._ascending, lc._descending, lc.project = None, "asc", "desc", "p"
    lc._list_pages = list_pages
    return lc


def test_raw_entries_paces_every_request_after_the_first_including_short_and_empty_pages(monkeypatch):
    fetches = []
    monkeypatch.setattr("cloudarmor_mcp.client.time.monotonic", lambda: 0.0)  # no time passes
    monkeypatch.setattr("cloudarmor_mcp.client.time.sleep", lambda s: fetches.append(f"sleep {s:g}"))
    lc = _lc([["a"], [], ["b", "c"], ["d"]], fetches)
    assert list(lc.raw_entries("f", 10, ascending=True, page_interval=5.0)) == ["a", "b", "c", "d"]
    # no wait after the last page: it carries no next-page token
    assert fetches == ["req", "sleep 5", "req", "sleep 5", "req", "sleep 5", "req"]


def test_raw_entries_stops_at_max_entries_without_another_request(monkeypatch):
    fetches = []
    monkeypatch.setattr("cloudarmor_mcp.client.time.sleep", lambda s: fetches.append("sleep"))
    lc = _lc([["a", "b"], ["c", "d"]], fetches)
    assert list(lc.raw_entries("f", 2)) == ["a", "b"]
    assert fetches == ["req"]


def test_raw_entries_retries_a_quota_error_once_before_the_first_entry(monkeypatch):
    class ResourceExhausted(Exception):
        pass

    slept = []
    monkeypatch.setattr("cloudarmor_mcp.client.time.sleep", lambda s: slept.append(s))
    lc = _lc([["a"], ["b"]], [], fail_first=ResourceExhausted)
    assert list(lc.raw_entries("f", 10, ascending=True, page_interval=5.0)) == ["a", "b"]
    assert slept[0] == 15  # the 429 back-off

    lc = _lc([], [], fail_first=ResourceExhausted)
    lc._list_pages = lambda *a: (_ for _ in ()).throw(ResourceExhausted("quota"))
    with pytest.raises(CloudArmorError):  # a second quota error is reported, not retried again
        list(lc.raw_entries("f", 10))


def test_list_pages_falls_back_to_the_sdk_generator_on_the_http_transport():
    from cloudarmor_mcp.client import LogClient

    class Api:  # JSONLoggingAPI has no _gapic_api
        pass

    class Client:
        logging_api = Api()

        def list_entries(self, **kw):
            return iter(["a", "b", "c", "d", "e"])

    lc = LogClient.__new__(LogClient)
    lc._client, lc.project = Client(), "p"
    assert list(lc._list_pages("f", "asc", 2)) == [(["a", "b"], True), (["c", "d"], True), (["e"], False)]


# --- traffic-export -----------------------------------------------------------


def _allowed(cache_hit=False, insert_id="t1"):
    payload = (
        {}
        if cache_hit
        else {
            "enforcedSecurityPolicy": {"name": "example-policy", "priority": 2147483647.0, "outcome": "ACCEPT"},
            "securityPolicyRequestData": {"remoteIpInfo": {"regionCode": "JP", "asn": 64496.0}},
        }
    )
    http = {
        "requestMethod": "GET",
        "requestUrl": "https://www.example.org/",
        "remoteIp": "2001:db8::7",
        "status": 200,
        "userAgent": "Mozilla/5.0",
        "cacheHit": cache_hit,
    }
    return FakeEntry(payload, http, ts=datetime(2026, 9, 23, 1, 2, 3, tzinfo=timezone.utc), insert_id=insert_id)


def test_sample_filter_matches_every_request_and_thins_by_insert_id():
    start, end = export.day_window("2026-09-23", "Asia/Tokyo", now=NOW)
    f = build_sample_filter(["a"], start, end, 0.01)
    assert f.startswith('resource.type="http_load_balancer" ')
    assert "DENY" not in f and "enforcedSecurityPolicy" not in f
    assert 'backend_service_name="a"' in f and 'timestamp < "2026-09-23T15:00:00Z"' in f
    assert f.endswith("sample(insertId, 0.01)")
    assert build_sample_filter([], start, end, 0.000001).endswith("sample(insertId, 0.000001)")  # no exponent
    assert build_sample_filter([], start, end, 0.0000014).endswith("sample(insertId, 0.0000014)")  # not rounded
    assert build_sample_filter([], start, end, 0.1).endswith("sample(insertId, 0.1)")
    assert "sample(" not in build_sample_filter([], start, end, 1)


@pytest.mark.parametrize("rate", [0, -0.5, 1.5, 0.0000001, "0.1", float("nan")])
def test_sample_filter_rejects_bad_rates(rate):
    start, end = export.day_window("2026-09-23", "UTC", now=NOW)
    with pytest.raises(CloudArmorError):
        build_sample_filter([], start, end, rate)


def test_record_cache_hit_is_a_boolean():
    assert export.entry_to_record(_allowed(cache_hit=True))["cache_hit"] is True
    assert export.entry_to_record(_allowed())["cache_hit"] is False
    assert export.entry_to_record(_deny())["cache_hit"] is False  # absent field
    assert export.entry_to_record(FakeEntry(None, None))["cache_hit"] is False


def test_traffic_export_document_keeps_cache_hits_and_records_the_rate():
    out = io.StringIO()
    fake = FakeClient([_allowed(insert_id="a"), _allowed(cache_hit=True, insert_id="b"), _deny(insert_id="c")])
    n = export.run_traffic_export(
        project="example-prod",
        backend_services=["web-backend"],
        date="2026-09-23",
        tz="Asia/Tokyo",
        sample=0.05,
        max_entries=100,
        out=out,
        client_factory=lambda p: fake,
        now=NOW,
    )
    doc = json.loads(out.getvalue())
    assert n == 3 and doc["schema"] == export.TRAFFIC_SCHEMA and doc["sample"] == 0.05 and "kind" not in doc
    assert [r["id"] for r in doc["entries"]] == ["a", "b", "c"]
    assert doc["entries"][1]["cache_hit"] is True and doc["entries"][1]["enforced"] is None
    assert doc["entries"][2]["enforced"]["outcome"] == "DENY"
    assert doc["filter"].endswith("sample(insertId, 0.05)") and fake.calls[0][1:] == (101, True)


@pytest.mark.parametrize("kw", [{"sample": 0}, {"sample": 2}, {"max_entries": 0}, {"date": "2026-09-24"}])
def test_traffic_export_rejects_bad_options_before_querying(kw):
    fake = FakeClient([])
    args = dict(
        project="p",
        backend_services=[],
        date="2026-09-23",
        tz="UTC",
        sample=0.01,
        max_entries=10,
        out=io.StringIO(),
        client_factory=lambda p: fake,
        now=NOW,
    )
    args.update(kw)
    with pytest.raises(export.ExportConfigError):
        export.run_traffic_export(**args)
    assert fake.calls == []


def test_deny_export_header_is_unchanged_apart_from_key_order():
    _, doc, _ = _run([_deny()])
    assert doc["schema"] == export.EXPORT_SCHEMA and doc["kind"] == "both" and "sample" not in doc
