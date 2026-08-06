# Reading the report

A `daily_brief` looks like this:

```text
# Cloud Armor brief — project example-prod, last 26h
## Enforced DENY: >= 2000 (capped at 2000)
  rule 101 (block non-home deep-path crawlers): 1803
  rule 500 (AutoDiscover probe block): 149
  rule 1002 (OWASP LFI protection): 35
## JP-sourced DENY (false-positive lens): 214, suspicious 12
  rule 1002 (OWASP LFI protection)  198.51.100.7  https://198.51.100.7/.git/config
  ...
## Preview DENY: 0
```

## Enforced DENY by rule

Your normal blocking volume, broken down by which rule fired. On its own a
large number is not a problem — a public site attracts constant scanning, and
blocking it is the WAF doing its job.

What is worth attention is a **change in the mix**: a rule that never fired
suddenly accounting for most denies, or a rule that used to fire dropping to
zero (which can mean the rule was edited, disabled, or that traffic now
matches an earlier rule instead).

!!! warning "`>= N (capped)` is a lower bound"
    When the query hits its cap the header shows `>= N (capped at N)`. The real
    total is larger — often much larger. Never compare a capped number against
    an uncapped one and conclude the volume fell. Raise `CLOUDARMOR_MAX_ENTRIES`
    or shorten `since_hours` if you need an exact figure.

## Home-region DENY (the false-positive lens)

Requests that geolocate to your own country or region and were blocked anyway.
This is the section that catches mistakes, because a rule aimed at foreign
scanners should rarely hit your own users.

Priorities listed in `known_normal_priorities` are folded into a suppressed
count. Everything else is printed with its source IP and request URL so you can
judge it:

| What you see | Verdict |
|---|---|
| Ordinary browsing paths from residential/mobile IPs, or a legitimate crawler | **Act** — likely a false positive; the rule is too broad |
| Requests to the load balancer's IP address rather than a hostname | Normal — that is a scanner, not a user |
| `.git/config`, `.env`, `wp-login.php`, path-traversal encodings | Normal — blocking these is correct even from inside your region |
| A single internal host generating many denies on one rule | Investigate — often a misconfigured internal tool, not an attack |

If the suspicious count is zero, the report says so explicitly rather than
printing nothing, so "no output" never has to be interpreted.

## Preview DENY

Rules running in dry-run mode: Cloud Armor records what they *would* have
blocked without blocking it. A preview rule that accumulates no home-region
hits over a sustained period is a candidate for promotion to enforce.

The reverse is equally informative — a preview rule that would have blocked
your own users tells you the rule needs narrowing before it goes live, and
costs nothing to learn.

## Practical cadence

Run `daily_brief` once a day over a window slightly longer than the interval
(the default `since_hours=26` covers a daily run with two hours of overlap, so
a late start never leaves a gap). Use `home_region_denies` on its own when you
want the false-positive detail without the surrounding sections.
