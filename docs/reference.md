# Reference

## Tools

All tools are read-only. Every one accepts `since_hours` (float, default 26)
except `health_check`.

### `daily_brief(since_hours=26)`

Morning summary in one call: enforced DENYs by rule priority, the home-region
false-positive lens (only when `CLOUDARMOR_HOME_REGION` is set), and preview
DENYs. A section whose query fails is rendered inline as
`query failed — <reason>`; the other sections still run.

### `enforce_denies(since_hours=26)`

Counts of enforced DENYs grouped by rule priority, highest first.

### `preview_denies(since_hours=26)`

Same, for rules in preview (dry-run) mode.

### `home_region_denies(since_hours=26)`

Enforced DENYs whose source IP geolocates to `CLOUDARMOR_HOME_REGION`.
Priorities in `known_normal_priorities` are counted and suppressed; the rest
are listed with source IP and request URL (40 lines maximum, then a count).
Returns an explanatory sentence instead of an error when the home region is
not configured.

### `health_check()`

Returns a fixed-shape dict — the keys never vary, so a monitoring caller does
not have to branch on their presence:

| Key | Meaning |
|---|---|
| `status` | `healthy` (config + probe query OK), `degraded` (config OK, probe failed), `error` (config unusable) |
| `service` | Always `cloudarmor-mcp` |
| `version` | Package version |
| `project` | Resolved project ID, or `null` |
| `backend_services` | Resolved filter list |
| `home_region` | Resolved region code, or `null` |
| `rules_ini` | `true` when a rules INI was loaded with content |
| `probe` | `ok`, or the failure reason |

## Environment variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `CLOUDARMOR_PROJECT` | yes | — | GCP project ID holding the load-balancer logs |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | — | Service-account key path (`roles/logging.viewer`) |
| `CLOUDARMOR_BACKEND_SERVICES` | no | all | Comma-separated backend service names |
| `CLOUDARMOR_HOME_REGION` | no | disabled | ISO region code for the false-positive lens |
| `CLOUDARMOR_RULES_INI` | no | none | Rule labels and known-normal priorities |
| `CLOUDARMOR_MAX_ENTRIES` | no | 2000 | Entries fetched per query; unparsable values fall back to the default |

## CLI

```bash
cloudarmor-mcp            # run as an MCP server over stdio
cloudarmor-mcp --version  # print version and exit
cloudarmor-mcp --check    # verify config + API access
cloudarmor-mcp --brief    # print daily_brief to stdout
```

Exit codes:

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `--check` | healthy | missing `CLOUDARMOR_PROJECT` | degraded (probe failed) |
| `--brief` | every section rendered | at least one section's query failed | — |

`--brief` is the convenient form for cron jobs and smoke tests: the non-zero
exit distinguishes "the WAF was quiet" from "we could not read the logs",
which a text report alone does not.

## Log filters

For reference, the Cloud Logging filters the server builds:

```text
resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
[jsonPayload.securityPolicyRequestData.remoteIpInfo.regionCode="JP"]
[resource.labels.backend_service_name="..." | =("a" OR "b")]
timestamp >= "<RFC3339 UTC>"
```

Preview queries substitute
`jsonPayload.previewSecurityPolicy.configuredAction="DENY"` for the outcome
line. Entries are fetched newest-first.
