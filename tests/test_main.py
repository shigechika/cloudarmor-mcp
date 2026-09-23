"""Tests for CLI dispatch and exit codes."""

import json

import pytest

from cloudarmor_mcp import __main__ as cli
from cloudarmor_mcp import export
from cloudarmor_mcp.client import CloudArmorError


class _Client:
    def __init__(self, entries=(), fail=None):
        self.entries, self.fail = list(entries), fail

    def raw_entries(self, filter_str, max_entries, ascending=False):
        if self.fail:
            raise self.fail
        yield from self.entries[:max_entries]


def _run(monkeypatch, argv, client=None, env=True):
    if env:
        monkeypatch.setenv("CLOUDARMOR_PROJECT", "example-prod")
        monkeypatch.setenv("CLOUDARMOR_BACKEND_SERVICES", "web-backend")
    else:
        monkeypatch.delenv("CLOUDARMOR_PROJECT", raising=False)
    monkeypatch.setattr(export, "LogClient", lambda project: client or _Client())
    monkeypatch.setattr("sys.argv", ["cloudarmor-mcp", *argv])
    with pytest.raises(SystemExit) as e:
        cli.main()
    return e.value.code


def test_deny_export_ok_writes_json_and_exits_0(monkeypatch, capsysbinary):
    rc = _run(monkeypatch, ["deny-export", "--date", "2020-01-01", "--tz", "Asia/Tokyo"])
    out = capsysbinary.readouterr().out
    assert rc == 0
    doc = json.loads(out.decode("utf-8"))
    assert doc["date"] == "2020-01-01" and doc["tz"] == "Asia/Tokyo" and doc["backend_services"] == ["web-backend"]


def test_deny_export_backend_override(monkeypatch, capsysbinary):
    rc = _run(monkeypatch, ["deny-export", "--date", "2020-01-01", "--backend", "a, b"])
    assert rc == 0
    assert json.loads(capsysbinary.readouterr().out)["backend_services"] == ["a", "b"]


def test_deny_export_missing_project_exits_2_with_empty_stdout(monkeypatch, capsysbinary):
    rc = _run(monkeypatch, ["deny-export", "--date", "2020-01-01"], env=False)
    assert rc == 2 and capsysbinary.readouterr().out == b""


@pytest.mark.parametrize(
    "argv",
    [
        ["deny-export", "--date", "2099-01-01"],
        ["deny-export", "--date", "20200101"],
        ["deny-export", "--date", "2020-01-01", "--tz", "Nowhere/City"],
        ["deny-export", "--date", "2020-01-01", "--max-entries", "0"],
        ["deny-export"],
    ],
)
def test_deny_export_bad_input_exits_2(monkeypatch, capsysbinary, argv):
    rc = _run(monkeypatch, argv)
    assert rc == 2 and capsysbinary.readouterr().out == b""


def test_deny_export_query_failure_exits_1(monkeypatch, capsysbinary):
    rc = _run(monkeypatch, ["deny-export", "--date", "2020-01-01"], client=_Client(fail=CloudArmorError("quota")))
    assert rc == 1 and capsysbinary.readouterr().out == b""


def test_version_flag_unchanged(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cloudarmor-mcp", "--version"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0 and capsys.readouterr().out.startswith("cloudarmor-mcp ")


def test_flags_without_project_still_exit_1(monkeypatch):
    monkeypatch.delenv("CLOUDARMOR_PROJECT", raising=False)
    monkeypatch.setattr("sys.argv", ["cloudarmor-mcp", "--brief"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1
