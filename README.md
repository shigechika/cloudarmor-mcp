<!-- mcp-name: io.github.shigechika/cloudarmor-mcp -->

# cloudarmor-mcp

English | [日本語](README.ja.md)

MCP server for [Google Cloud Armor](https://cloud.google.com/armor) WAF log patrol — deny summaries per rule, home-region false-positive checks, and preview (dry-run) rule review, straight from Cloud Logging.

Built for a daily "is the WAF healthy?" patrol: one `daily_brief` call answers *what did we block, did we block anyone we shouldn't have, and are the preview rules ready to promote*.

Documentation: <https://shigechika.github.io/cloudarmor-mcp/>

## Tools

| Tool | Purpose |
|---|---|
| `daily_brief` | One-call morning summary: enforced DENYs by rule priority, home-region false-positive lens, preview DENYs |
| `enforce_denies` | Enforced DENY counts per rule priority |
| `home_region_denies` | Enforced DENYs whose source IP geolocates to your home region — anything not marked known-normal is a false-positive candidate |
| `preview_denies` | Preview (dry-run) DENY counts — a quiet preview rule is a promotion candidate |
| `health_check` | Version, config presence, and a minimal Cloud Logging probe |

All tools are read-only. Counts are hard-capped (default 2000 entries per query) and a capped result is reported as `>= N (capped)`, never as an exact total.

## Setup

### 1. Least-privilege service account

Create a service account with **`roles/logging.viewer` only** and download a key. Unlike human accounts, service accounts are not subject to organization re-authentication policies, so an unattended patrol never silently expires.

```bash
gcloud iam service-accounts create waf-log-viewer --project=YOUR_PROJECT
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member=serviceAccount:waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com \
  --role=roles/logging.viewer
gcloud iam service-accounts keys create key.json \
  --iam-account=waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com
```

### 2. Install

```bash
pip install cloudarmor-mcp
# or
uv tool install cloudarmor-mcp
```

### 3. Environment variables

| Variable | Required | Meaning |
|---|---|---|
| `CLOUDARMOR_PROJECT` | yes | GCP project ID that receives the load-balancer logs |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | Path to the service-account key file |
| `CLOUDARMOR_BACKEND_SERVICES` | no | Comma-separated backend service names to filter (default: all) |
| `CLOUDARMOR_HOME_REGION` | no | ISO region code treated as home traffic, e.g. `JP`. Enables the false-positive lens |
| `CLOUDARMOR_RULES_INI` | no | Path to a rules INI (labels + known-normal priorities, see below) |
| `CLOUDARMOR_MAX_ENTRIES` | no | Max entries fetched per query (default 2000) |

### 4. Optional rules INI

Keep your rule numbering out of prompts and give the reports human-readable labels:

```ini
[rules]
101 = block non-home deep-path crawlers
500 = AutoDiscover probe block
1002 = OWASP LFI protection

[home]
; home-region DENYs on these priorities are expected, not false positives
known_normal_priorities = 500, 600
```

### 5. Claude Code

```bash
claude mcp add cloudarmor -- cloudarmor-mcp
```

with the environment variables above in the server's env.

## CLI

```bash
cloudarmor-mcp --version   # print version
cloudarmor-mcp --check     # config + API probe (exit 0 when healthy)
cloudarmor-mcp --brief     # print daily_brief to stdout (cron / smoke tests)
```

## Reading the report

- **Enforced DENY by rule** — your normal blocking volume. Sudden shifts in the mix are worth a look.
- **Home-region DENY** — requests from your own country/region that were blocked. Legitimate users and legitimate crawlers being denied show up here; scanner traffic that happens to originate locally will too, so the `known_normal_priorities` list keeps expected rules (e.g. an AutoDiscover block) out of the suspicious list.
- **Preview DENY** — rules in dry-run. A preview rule that stays free of home-region hits over time is a candidate for promotion to enforce.

## License

MIT
