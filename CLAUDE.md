# CLAUDE.md

Guidance for AI assistants (and humans) editing this repository.

This file covers **how to work here**: commands, layout, conventions, and
the traps. Two sibling files carry the other halves and are not repeated
here — `.github/copilot-instructions.md` explains *why* the invariants
exist, and `REVIEW.md` decides what a reviewer treats as blocking.

## What this repository is

An MCP server that reads Google Cloud Armor WAF deny logs out of Cloud
Logging and reports them: per-rule counts, a home-region false-positive
lens, and preview (dry-run) rule review. Built on the official MCP
Python SDK (`mcp.server.fastmcp`), published to PyPI as
`cloudarmor-mcp`.

**Read-only by design.** Every tool only reads Cloud Logging, and the
service account is documented as holding `roles/logging.viewer` and
nothing else. That is a security posture the deployment guide promises
to operators, not just a feature boundary.

## Commands

```bash
uv sync --dev                       # install, including pytest + ruff
uv run pytest                       # unit tests (no network, no GCP creds)
uv run ruff check .                 # lint    — gated in CI
uv run ruff format --check .        # format  — gated in CI (see the trap below)
uv run cloudarmor-mcp --check       # live health probe against a real project
uv run cloudarmor-mcp --brief       # render the daily brief to stdout
uv run python scripts/smoke_test.py # every tool against a real project
```

`tests/` runs without network access or Google credentials:
`test_client.py` covers filter construction and config parsing,
`test_server.py` injects a fake log client. The live check is
`scripts/smoke_test.py`, run on a schedule against a deployed instance —
it is deliberately not part of the unit suite.

### CLI exit codes (`cloudarmor_mcp/__main__.py`)

| Invocation | 0 | 1 | 2 |
|---|---|---|---|
| `--check` | healthy | `CLOUDARMOR_PROJECT` unset | degraded (probe failed) |
| `--brief` | every section rendered | any section's query failed | — |

`scripts/smoke_test.py` exits 1 only on `FAIL` or `NO_SPEC`. `OK`,
`SKIP` **and `RESTRICTED`** all exit 0 — `RESTRICTED` is easy to miss
when reasoning about that contract.

## Architecture

- `cloudarmor_mcp/server.py` — the FastMCP server and all five tools:
  `health_check`, `enforce_denies`, `preview_denies`,
  `home_region_denies`, `daily_brief`. Also holds the module-level
  `_CLIENT` singleton (`_client()` / `reset_client()`), the shared
  `_collect()` query path, `_count_fragment()` (the cap notation) and
  `_load_rules_safe()`.
- `cloudarmor_mcp/client.py` — `LogClient`: Cloud Logging filter
  construction and entry fetching.
- `cloudarmor_mcp/rules.py` — `load_rules()`, the optional
  `CLOUDARMOR_RULES_INI` parser producing labels and
  `known_normal_priorities`.
- `cloudarmor_mcp/__main__.py` — console script (`cloudarmor-mcp`),
  `--check` and `--brief`.
- `scripts/smoke_harness.py` — a **verbatim shared copy** used by
  sibling MCP servers and drift-checked across repositories. Changes
  belong upstream, not here.
- `scripts/smoke_probes.py` — one probe per registered tool. It is a
  third pinning site for output contracts, alongside the unit tests and
  the report headlines: `health_check`'s key subset and `status` values
  are pinned here by `require_keys` and a regex.
- `docs/` — MkDocs site, every page in an English/Japanese pair.

## Conventions

- Code, comments, docstrings, commit messages and English documentation
  are in English. `README.ja.md` and `docs/*.ja.md` are the Japanese
  translations; when one side of a pair changes materially, the other
  should follow.
- Versions are release-please's (`release-type: python`). It owns
  `cloudarmor_mcp/__init__.py`, both `version` fields in `server.json`,
  **and `CHANGELOG.md`**. Never hand-edit any of them; the release
  workflow verifies the three version sites agree with the tag and
  fails loudly if not.
- No site-specific values anywhere — project IDs, backend service
  names, rule numbers, addresses, hostnames — in code, tests or
  documentation examples. This package is public and must stay reusable
  by other organizations. Documentation uses RFC 5737 / RFC 3849
  placeholders (`198.51.100.7`, `example-prod`).
- Configuration is environment-driven (`CLOUDARMOR_PROJECT`,
  `CLOUDARMOR_MAX_ENTRIES`, `CLOUDARMOR_RULES_INI`, home-region
  settings), with the INI optional.

## Traps

- **`ruff format --check .` formats Markdown, not just Python.** ruff
  0.16.1 reports *22 files* here: 10 `.py` minus `scripts/smoke_harness.py`
  (excluded from formatting only, via `format.exclude` — `ruff check`
  still lints it) plus **13 Markdown files**. So editing `README.md`,
  `CHANGELOG.md`, `REVIEW.md`, `copilot-instructions.md` or anything
  under `docs/` can red the `lint` job in `ci.yml`. Run
  `uv run ruff format --check .` after a docs-only change too.
- **`scripts/smoke_harness.py` is lint-but-not-format.** `ruff check`
  still covers it while the "never touch it, changes belong upstream"
  rule stands. A future ruff release adding a rule that fires there will
  red CI, and the only local fix is a `noqa` — which is itself drift
  from the shared copy. Coordinate upstream rather than patching here.
- **The rules-INI failure surface is narrower than it looks.** An
  existing-but-unreadable INI is surfaced by `_load_rules_safe()`, but a
  `CLOUDARMOR_RULES_INI` pointing at a path that **does not exist** is
  silently treated as "no rules configured" (`rules.py`'s
  `os.path.isfile` guard). `health_check`'s `rules_ini` reports whether
  any rules were *loaded*, not whether the variable was set.
- **`_load_rules_safe()` renders its warning two different ways.** The
  four text-returning tools append a `[warn] ...` line; `health_check`
  folds the same text into its `probe` string after a `; `. Anything
  parsing `probe` for an exact value has to account for that.
- **`Config.from_env()` is only guarded in `health_check`.** The four
  text tools reach it unguarded (via `_collect()`, or directly in
  `home_region_denies` and `_daily_brief_text`), so on an unconfigured
  server they raise rather than degrading. `health_check` is the tool
  that answers "is this thing configured".
- **Python 3.11 is installable but untested.** `requires-python` is
  `>=3.10`, while the CI matrix and the trove classifiers both list
  3.10 / 3.12 / 3.13 only. The two lists agree with each other, so this
  looks deliberate — but a 3.11 user is on an untested interpreter.
- **`google-cloud-logging>=3,<4` has an upper bound with no recorded
  rationale**, unlike `mcp>=1.2,<2` which has three (SDK 2.0 removed
  `mcp.server.fastmcp`). Dependabot does **not** ignore majors for
  `google-cloud-logging`, so a v4 pull request will show up and nothing
  on record says whether to take it.
- **`_CLIENT` is a module global and test isolation is partial.** Only
  the `env` fixture resets it. Two tests in `tests/test_server.py` do
  not use that fixture, and one of them calls `reset_client()` by hand
  before but not after. A new test that builds a client should reset it
  rather than assume a clean slate.
