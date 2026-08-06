# Copilot review instructions — cloudarmor-mcp

An MCP server that reads Google Cloud Armor WAF deny logs out of Cloud Logging
and reports them: per-rule counts, a home-region false-positive lens, and
preview (dry-run) rule review. Built on the official MCP Python SDK
(`mcp.server.fastmcp`), published to PyPI as `cloudarmor-mcp`.

Review against the properties below. They are specific to this repository —
skip generic advice that any Python project would receive.

## This is a read-only server, and that is load-bearing

Every tool only reads Cloud Logging. The service account it authenticates with
is expected to hold `roles/logging.viewer` and nothing else, and the docs tell
operators to create it that way.

- Flag any new call that mutates state (Cloud Armor policy edits, log
  exclusions, writing back to GCP) — that would break the security model the
  deployment guide promises, not just add a feature.
- A tool that acquires broader scopes than log reading needs the same scrutiny.

## Never let a truncated count read as a total

Queries are capped (`CLOUDARMOR_MAX_ENTRIES`, default 2000). When the cap is
hit, reports must print `>= N (capped at N)` — this is what `_count_fragment`
in `server.py` exists for.

- A new report path that formats `len(entries)` directly, bypassing
  `_count_fragment`, is a defect: it turns a lower bound into an apparent
  exact figure, and the whole point of the cap notation is that a busy day
  must not be mistaken for a quiet one.
- `_collect` returns `(entries, cap)` for this reason. A caller that discards
  the cap loses the ability to flag truncation.

## Rule priorities arrive as floats

Cloud Logging returns `jsonPayload.*SecurityPolicy.priority` as a JSON number,
so a priority shows up as `101.0`. `_normalize_priority` in `client.py` folds
integral floats back to `"101"` so they match the plain integers operators
write in the rules INI.

- Any new code path that reads a priority must go through that normalization,
  or label lookup and `known_normal_priorities` matching will silently miss.
- This was a real bug found in the first live run; do not regress it.

## No site-specific values in the repository

Project ID, backend service names, home region and rule numbering all come
from environment variables or the optional INI (`CLOUDARMOR_RULES_INI`). The
package is public and must stay reusable by other organizations.

- Flag hardcoded project IDs, backend service names, rule numbers, IP
  addresses or hostnames anywhere in code, tests, or docs examples.
- Documentation examples should use RFC 5737 / RFC 3849 style placeholders
  (`198.51.100.7`, `example-prod`) rather than real infrastructure.

## Log data must not leak into aggregate output

Summary tools (`enforce_denies`, `preview_denies`, and the corresponding
`daily_brief` sections) report priorities and counts only. Source IPs and
request URLs appear solely in `home_region_denies` and its `daily_brief`
section, where inspecting them is the purpose of the check.

- Flag additions that put request URLs, IPs, headers or user agents into the
  summary sections or into exception messages that callers log.

## Dependency pins are deliberate

`pyproject.toml` pins `mcp>=1.2,<2`.

- The upper bound is intentional: SDK 2.0 removed `mcp.server.fastmcp`, which
  this server imports. Do not suggest widening it. `.github/dependabot.yml`
  ignores major updates for `mcp` for the same reason.
- The lower bound is also intentional: `mcp.server.fastmcp` first appeared in
  1.2.0, so `mcp>=1.0` would allow releases that cannot import this server.

## Structural conventions

- **`health_check` shape is a contract.** It returns a fixed set of keys
  (`status`, `service`, `version`, `project`, `backend_services`,
  `home_region`, `rules_ini`, `probe`) on every path, including the error
  path, so a monitoring caller never branches on key presence. Flag changes
  that drop or conditionally add keys. `status` is `healthy` / `degraded` /
  `error`.
- **Config parsing must fail loudly, not silently.** `load_rules` opens the
  INI itself rather than relying on `configparser.read()`, which swallows
  `OSError` per file — a permission-denied config must not look identical to
  "nothing configured". `_load_rules_safe` in `server.py` is the deliberate
  catch point for reporting that to the user as a warning line.
- **`scripts/smoke_harness.py` is a verbatim shared copy** used by sibling MCP
  servers and drift-checked across repositories. Do not suggest refactoring,
  reformatting or "improving" it here; changes belong upstream. It is excluded
  from `ruff format` for exactly this reason (`ruff check` still applies).
- **`server.json` feeds the MCP Registry.** Its `description` must stay at or
  under 100 characters, and `README.md` must keep the
  `<!-- mcp-name: io.github.shigechika/cloudarmor-mcp -->` marker at the top —
  the registry validates PyPI ownership by finding that marker in the
  published README. Both were learned by having releases rejected.
- **release-please owns versions.** `cloudarmor_mcp/__init__.py`,
  `server.json` (two places) and the tag are updated by the release PR. Do not
  suggest hand-editing a version; the release workflow verifies all three
  agree with the tag and fails loudly if not.

## Tests

`tests/` runs without network access or Google credentials: `test_client.py`
covers filter construction and config parsing, `test_server.py` injects a fake
log client. CI runs Python 3.10 / 3.12 / 3.13 on Linux plus 3.12 on Windows.

- New behaviour should be testable the same way. Flag tests that would require
  live GCP access to run.
- The live check against a real project lives in `scripts/smoke_test.py`, which
  is run on a schedule against a deployed instance — not in the unit suite.

## Language

Code, comments, docstrings, commit messages and English documentation are in
English. `README.ja.md` and `docs/*.ja.md` are the Japanese translations; when
one side of a pair changes materially, the other should follow.
