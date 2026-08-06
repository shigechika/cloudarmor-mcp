"""Optional site-specific rule annotations for daily_brief.

Loaded from an INI file pointed to by ``CLOUDARMOR_RULES_INI``. This keeps
organization-specific Cloud Armor rule numbering out of the codebase so the
server stays generic and publishable. When unset or missing, priorities are
reported without labels and no home-region priority is treated as known-normal.

Example::

    [rules]
    ; label shown next to each rule priority in reports
    101 = block non-home deep-path crawlers
    500 = AutoDiscover probe block
    1002 = OWASP LFI protection

    [home]
    ; home-region DENYs on these priorities are expected (not false positives)
    known_normal_priorities = 500, 600
"""

import configparser
import os
from dataclasses import dataclass, field


@dataclass
class Rules:
    labels: dict[str, str] = field(default_factory=dict)
    known_normal: set[str] = field(default_factory=set)

    def label(self, priority: str) -> str:
        name = self.labels.get(priority)
        return f" ({name})" if name else ""

    def is_known_normal(self, priority: str) -> bool:
        return priority in self.known_normal


def load_rules(path: str | None = None) -> Rules:
    """Load rule annotations (env ``CLOUDARMOR_RULES_INI`` by default).

    Returns empty Rules when no path is configured or the file is absent.
    Raises ``configparser.Error``, ``OSError`` or ``UnicodeDecodeError`` when
    the path exists but cannot be parsed — callers that must not crash on a
    bad config should catch those.
    """
    path = path or os.environ.get("CLOUDARMOR_RULES_INI")
    if not path or not os.path.isfile(path):
        return Rules()
    parser = configparser.ConfigParser()
    with open(path, encoding="utf-8") as f:
        parser.read_file(f)
    labels: dict[str, str] = {}
    if parser.has_section("rules"):
        labels = {k.strip(): v.strip() for k, v in parser.items("rules")}
    known: set[str] = set()
    if parser.has_section("home"):
        raw = parser.get("home", "known_normal_priorities", fallback="")
        known = {p.strip() for p in raw.split(",") if p.strip()}
    return Rules(labels=labels, known_normal=known)
