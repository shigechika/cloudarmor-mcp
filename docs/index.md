# cloudarmor-mcp

MCP server for [Google Cloud Armor](https://cloud.google.com/armor) WAF log patrol — deny summaries per rule, home-region false-positive checks, and preview (dry-run) rule review, straight from Cloud Logging.

Built for a daily "is the WAF healthy?" patrol: one `daily_brief` call answers *what did we block, did we block anyone we shouldn't have, and are the preview rules ready to promote*.

## Tools

| Tool | Purpose |
|---|---|
| `daily_brief` | One-call morning summary: enforced DENYs by rule priority, home-region false-positive lens, preview DENYs |
| `enforce_denies` | Enforced DENY counts per rule priority |
| `home_region_denies` | Enforced DENYs whose source IP geolocates to your home region — anything not marked known-normal is a false-positive candidate |
| `preview_denies` | Preview (dry-run) DENY counts — a quiet preview rule is a promotion candidate |
| `health_check` | Version, config presence, and a minimal Cloud Logging probe |

Every tool is read-only: the server never writes to Cloud Armor or Cloud Logging, and the service account it authenticates with carries `roles/logging.viewer` and nothing else.

## Design notes

**Counts are never silently truncated.** Each query is capped (2000 entries by default). When the cap is reached the report says `>= N (capped at N)` rather than printing a number that looks exact. A capped count is a lower bound, and reports that treat it as a total are how a busy day gets mistaken for a quiet one.

**Site-specific values stay out of the code.** Project, backend services, home region and rule numbering all come from the environment or an optional INI file, so the same package works unmodified across organizations — and rule numbers never have to be pasted into prompts.

**No log payloads in aggregate output.** The summary tools report priorities and counts. Source IPs and request URLs appear only in `home_region_denies` (and the corresponding `daily_brief` section), where they are the point of the check.

## Next steps

- [Setup](setup.md) — service account, installation, environment, rules INI
- [Reading the report](reading.md) — what each section means and when to act
- [Reference](reference.md) — tool arguments, environment variables, CLI, exit codes
