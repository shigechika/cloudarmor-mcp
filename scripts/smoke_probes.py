"""Probe specs for this server's tools — the Cloud Armor-specific half of the smoke test.

Every registered tool needs an entry here (the harness fails on a tool with no
spec), so adding a tool forces a decision: how would we know it works?

Three constraints shape everything below.

**Read-only.** Every tool on this server only reads Cloud Logging (the service
account carries roles/logging.viewer and nothing else), so no probe is skipped
for safety — the full surface is exercised on every run.

**No site-specific values in this file.** This repository is public, so a probe
may not name a project, backend service or rule priority from the installation
it runs against. The tools take no such arguments anyway — everything comes
from the server's own environment.

**Bounded.** A probe runs on a schedule against a paid log API, so every probe
narrows the window to one hour instead of the tools' 26-hour patrol default.

Assertions are shape-first: these tools answer with formatted text whose empty
case is a headline with a zero count, not an error, so a probe pins the header
line it must produce. A quiet WAF hour is a real observation — the probes
accept it and assert the envelope instead.
"""

from smoke_harness import Probe

# One hour keeps the log scan cheap; the header echoes the window ("last 1h"),
# so the patterns below pin it to prove the argument actually took effect.
WINDOW = {"since_hours": 1}

PROBES: dict[str, Probe] = {
    # -- server / backend health ------------------------------------------
    "health_check": Probe(
        require_keys=("status", "service", "version", "project", "probe"),
        must_match=(r'"status": "(healthy|degraded)"',),
        allow_empty=True,
    ),
    # -- deny summaries ----------------------------------------------------
    # A quiet hour renders "…: 0" with no rule table; what must hold is that
    # the tool produced its headline and not an error rendering.
    "enforce_denies": Probe(
        args=WINDOW,
        must_match=(r"^Enforced DENY, last 1h: (>= )?\d+",),
        must_not_match=(r"query failed",),
    ),
    "preview_denies": Probe(
        args=WINDOW,
        must_match=(r"^Preview DENY, last 1h: (>= )?\d+",),
        must_not_match=(r"query failed",),
    ),
    # The home-region lens is optional configuration: without
    # CLOUDARMOR_HOME_REGION the tool answers with its "not set" sentence,
    # which is a correct deployment state, not a failure.
    "home_region_denies": Probe(
        args=WINDOW,
        must_match=(
            r"^Enforced DENY from region \S+, last 1h: (>= )?\d+"
            r"|^CLOUDARMOR_HOME_REGION is not set",
        ),
        must_not_match=(r"query failed",),
    ),
    # -- morning patrol ----------------------------------------------------
    # The brief is a document: assert its frame (title + the one section that
    # is always emitted) rather than any particular finding. Inline
    # "query failed —" lines are exactly what this run exists to notice.
    "daily_brief": Probe(
        args=WINDOW,
        must_match=(r"^# Cloud Armor brief — project .+, last 1h", r"^## Enforced DENY:"),
        must_not_match=(r"query failed",),
        timeout=300,
    ),
}
