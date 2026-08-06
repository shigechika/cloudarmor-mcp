# Setup

## 1. A least-privilege service account

Create a service account with **`roles/logging.viewer` only** and download a key:

```bash
gcloud iam service-accounts create waf-log-viewer --project=YOUR_PROJECT
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member=serviceAccount:waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com \
  --role=roles/logging.viewer
gcloud iam service-accounts keys create key.json \
  --iam-account=waf-log-viewer@YOUR_PROJECT.iam.gserviceaccount.com
```

!!! tip "Why not a human account"
    Organizations commonly enforce a re-authentication policy on human Google
    accounts: the refresh token stays valid but obtaining an access token
    demands an interactive identity check every day or so. A background patrol
    running as a human account therefore fails with
    `Reauthentication failed` at an unpredictable hour, and the failure looks
    like an outage rather than a policy. Service accounts are exempt, which is
    why this server is built around one.

Keep the key at mode `600` and out of version control.

## 2. Install

```bash
pip install cloudarmor-mcp
# or
uv tool install cloudarmor-mcp
```

## 3. Environment

| Variable | Required | Meaning |
|---|---|---|
| `CLOUDARMOR_PROJECT` | yes | GCP project ID that receives the load-balancer logs |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | Path to the service-account key file |
| `CLOUDARMOR_BACKEND_SERVICES` | no | Comma-separated backend service names to filter (default: all) |
| `CLOUDARMOR_HOME_REGION` | no | ISO region code treated as home traffic, e.g. `JP`. Enables the false-positive lens |
| `CLOUDARMOR_RULES_INI` | no | Path to a rules INI (see below) |
| `CLOUDARMOR_MAX_ENTRIES` | no | Max entries fetched per query (default 2000) |

Find your backend service names with:

```bash
gcloud compute backend-services list --project=YOUR_PROJECT --format='value(name)'
```

Leaving `CLOUDARMOR_BACKEND_SERVICES` unset queries every backend in the
project, which is correct when one load balancer serves everything and noisy
when several do.

## 4. Rules INI (optional)

Rule priorities are just numbers in the log. This file gives them names and
tells the home-region lens which ones are expected:

```ini
[rules]
101 = block non-home deep-path crawlers
500 = AutoDiscover probe block
1002 = OWASP LFI protection

[home]
; home-region DENYs on these priorities are expected, not false positives
known_normal_priorities = 500, 600
```

Both sections are optional. Without `[rules]` the reports show bare priority
numbers; without `[home]` every home-region deny is listed as suspicious.

!!! note "Priorities are matched as integer strings"
    Cloud Logging returns rule priorities as JSON numbers, so a priority
    arrives as `101.0`. The server folds integral floats back to `101` before
    matching, so write plain integers in the INI — `101`, not `101.0`.

## 5. Register with an MCP client

Claude Code:

```bash
claude mcp add cloudarmor -- cloudarmor-mcp
```

Set the environment variables above in the server's environment. Verify the
whole chain — config, credentials and API access — before wiring it into a
scheduled patrol:

```bash
cloudarmor-mcp --check   # exit 0 and "healthy — cloudarmor-mcp <version> project=<id>"
```
