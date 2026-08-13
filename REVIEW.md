# Review rules for this repository

Review rules on top of the reviewer's default focus. Three things:
which findings are blocking here, which classes to report that the
default focus would otherwise skip, and which are noise. The reasoning
behind the rules lives in `.github/copilot-instructions.md`, which the
reviewer also receives.

## Always blocking

- **Any call that mutates state, or a tool acquiring scopes beyond log
  reading.** Every tool only reads Cloud Logging, and the service
  account is documented as holding `roles/logging.viewer` and nothing
  else. A Cloud Armor policy edit, a log exclusion, or any write back
  to GCP breaks the security model the deployment guide promises to
  operators — it is not merely a new feature.
- **A truncated count formatted as an exact one.** Queries are capped
  at `CLOUDARMOR_MAX_ENTRIES`, and `_count_fragment` exists so a capped
  result reads `>= N (capped at N)`. A report path that formats
  `len(entries)` directly turns a lower bound into an apparent total,
  which is exactly how a busy day gets mistaken for a quiet one. A
  caller that discards the `cap` half of `_collect`'s `(entries, cap)`
  return belongs here too — it throws away the ability to flag
  truncation at all.
- **A priority read without `_normalize_priority`.** Cloud Logging
  returns `jsonPayload.*SecurityPolicy.priority` as a JSON number, so
  `101` arrives as `101.0`; the normalization folds integral floats
  back to `"101"` to match the plain integers operators write in the
  rules INI. Skipping it makes label lookup and
  `known_normal_priorities` matching silently miss. This was a real bug
  found on the first live run.
- **A site-specific value committed anywhere** — a project ID, backend
  service name, rule number, IP address or hostname, in code, tests or
  documentation examples. This package is public and must stay reusable
  by other organizations. Documentation should use RFC 5737 / RFC 3849
  placeholders (`198.51.100.7`, `example-prod`).
- **Log data leaking into aggregate output.** `enforce_denies`,
  `preview_denies` and their `daily_brief` sections report priorities
  and counts only. Request URLs, source IPs, headers and user agents
  belong solely to `home_region_denies` and its `daily_brief` section,
  where inspecting them is the point — including in exception messages
  a caller might log.
- **A change to `health_check`'s key set.** It returns `status`,
  `service`, `version`, `project`, `backend_services`, `home_region`,
  `rules_ini` and `probe` on **every** path including the error path,
  so a monitoring caller never has to branch on key presence. Dropping
  a key, or adding one conditionally, breaks that contract.
- **Widening the `mcp>=1.2,<2` pin.** The upper bound is deliberate:
  SDK 2.0 removed `mcp.server.fastmcp`, which this server imports, and
  `.github/dependabot.yml` ignores major updates for the same reason.
  The lower bound is deliberate too — `mcp.server.fastmcp` first
  appeared in 1.2.0.

## Report even though the default focus would not

- **Config parsing that fails silently.** `load_rules` opens the INI
  itself rather than relying on `configparser.read()`, which swallows
  `OSError` per file, so a permission-denied config does not look
  identical to "nothing configured"; `_load_rules_safe` is the
  deliberate catch point that surfaces it as a warning line. A new
  parse path that reverts to the silent shape is the finding.
- **A test that would need live GCP access or credentials to run.**
  `tests/` runs without either — `test_client.py` covers filter
  construction and config parsing, `test_server.py` injects a fake log
  client. The live check lives in `scripts/smoke_test.py`, run on a
  schedule against a deployed instance, not in the unit suite.
- **A `server.json` description over 100 characters, or a `README.md`
  missing its `<!-- mcp-name: ... -->` marker at the top.** The MCP
  Registry validates PyPI ownership by finding that marker in the
  published README, and both constraints were learned by having
  releases rejected.
- **A material change to one side of a bilingual documentation pair
  without the other**, as advisory: `README.md` / `README.ja.md`, and
  `docs/*.md` / `docs/*.ja.md`.

## Never report

- Anything about `scripts/smoke_harness.py`'s structure, formatting or
  factoring. It is a verbatim shared copy used by sibling MCP servers
  and drift-checked across repositories, so changes belong upstream,
  not here. It is excluded from `ruff format` for that reason —
  `ruff check` still applies to it.
- A request to hand-edit a version. release-please owns
  `cloudarmor_mcp/__init__.py`, both places in `server.json`, and the
  tag; the release workflow verifies all three agree and fails loudly
  if not.
- Suggestions to hand-build an MCP content envelope
  (`{"content": [...], "isError": ...}`) inside a tool handler. This
  server is built on `mcp.server.fastmcp`, which wraps returned values
  already.
- Anything `ruff check .` or `ruff format --check .` already fails the
  build on. Both gate this repository, so restating a finding costs a
  round trip and no information.
