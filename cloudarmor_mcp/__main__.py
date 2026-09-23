"""Entry point for cloudarmor-mcp."""

import argparse
import asyncio
import contextlib
import os
import sys

from cloudarmor_mcp import __version__


def _deny_export(argv: list[str]) -> int:
    """`cloudarmor-mcp deny-export ...`: one day of DENY entries as JSON on stdout.

    Exit 0 exported, 1 the Cloud Logging query failed (stdout may then hold an
    unterminated document) or the reader closed the pipe, 2 usage or
    configuration error — including an unset CLOUDARMOR_PROJECT and a client
    that cannot be created (credentials), unlike --check/--brief which exit 1.
    """
    from cloudarmor_mcp import export
    from cloudarmor_mcp.client import CloudArmorError, Config

    parser = argparse.ArgumentParser(
        prog="cloudarmor-mcp deny-export",
        description="Export one calendar day of Cloud Armor DENY log entries as JSON (per entry, for batch use)",
    )
    parser.add_argument("--date", required=True, help="calendar day, YYYY-MM-DD, in --tz; must have ended")
    parser.add_argument("--tz", default="UTC", help="IANA time zone of --date (default UTC)")
    parser.add_argument("--kind", choices=export.KINDS, default="both", help="which DENY outcome to export")
    parser.add_argument(
        "--max-entries",
        type=int,
        default=export.DEFAULT_MAX_ENTRIES,
        help=f"stop after this many entries and set capped (default {export.DEFAULT_MAX_ENTRIES})",
    )
    parser.add_argument(
        "--backend", default=None, help="comma-separated backend service names (default CLOUDARMOR_BACKEND_SERVICES)"
    )
    args = parser.parse_args(argv)
    try:
        cfg = Config.from_env()
    except CloudArmorError as e:
        print(f"deny-export: {e}", file=sys.stderr)
        return 2
    backends = cfg.backend_services
    if args.backend is not None:
        backends = [b.strip() for b in args.backend.split(",") if b.strip()]
    try:
        client = export.LogClient(cfg.project)
    except CloudArmorError as e:  # missing library or credentials: configuration, not a query failure
        print(f"deny-export: {e}", file=sys.stderr)
        return 2
    out = export.utf8_stdout()
    try:
        n = export.run_export(
            project=cfg.project,
            backend_services=backends,
            date=args.date,
            tz=args.tz,
            kind=args.kind,
            max_entries=args.max_entries,
            out=out,
            client=client,
        )
    except export.ExportConfigError as e:
        print(f"deny-export: {e}", file=sys.stderr)
        return 2
    except CloudArmorError as e:
        print(f"deny-export: failed: {e}", file=sys.stderr)
        return 1
    except BrokenPipeError:  # the reader went away (e.g. `| head`); nothing left to write
        with contextlib.suppress(OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        print("deny-export: stdout closed by the reader", file=sys.stderr)
        return 1
    finally:
        with contextlib.suppress(BrokenPipeError, OSError, ValueError):
            out.flush()
            out.detach()
    print(f"deny-export: {n} entries for {args.date} ({args.tz})", file=sys.stderr)
    return 0


def main():
    if sys.argv[1:2] == ["deny-export"]:
        sys.exit(_deny_export(sys.argv[2:]))
    parser = argparse.ArgumentParser(
        description="Google Cloud Armor WAF log patrol MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Required environment variables:
  CLOUDARMOR_PROJECT              GCP project ID that receives the LB logs
  GOOGLE_APPLICATION_CREDENTIALS  Service-account key (roles/logging.viewer)

Optional environment variables:
  CLOUDARMOR_BACKEND_SERVICES  Comma-separated backend service names to filter
  CLOUDARMOR_HOME_REGION       ISO region code treated as home (e.g. JP)
  CLOUDARMOR_RULES_INI         Rule-priority labels / known-normal priorities

Subcommands:
  deny-export --date YYYY-MM-DD [--tz ZONE] [--kind both|enforced|preview]
                               Export one day of DENY entries as JSON (see deny-export --help)
""",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--check", action="store_true", help="Verify config and API access, then exit")
    parser.add_argument(
        "--brief",
        action="store_true",
        help="Print the daily_brief to stdout and exit (handy for cron / smoke tests)",
    )
    args = parser.parse_args()

    if args.version:
        print(f"cloudarmor-mcp {__version__}")
        sys.exit(0)

    if not os.environ.get("CLOUDARMOR_PROJECT"):
        print("Error: missing environment variable: CLOUDARMOR_PROJECT", file=sys.stderr)
        sys.exit(1)

    if args.check:
        from cloudarmor_mcp.server import health_check

        result = health_check()
        print(f"{result['status']} — {result['service']} {result['version']} project={result['project']}")
        if result["probe"] != "ok":
            print(f"probe: {result['probe']}", file=sys.stderr)
        sys.exit(0 if result["status"] == "healthy" else 2)

    if args.brief:
        from cloudarmor_mcp.server import DEFAULT_SINCE_HOURS, _daily_brief_text

        text, had_error = _daily_brief_text(DEFAULT_SINCE_HOURS)
        print(text)
        sys.exit(1 if had_error else 0)

    from cloudarmor_mcp.server import mcp

    try:
        mcp.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        # anyio's teardown on SIGINT dumps a 20-80 line traceback. What it
        # raises out of mcp.run() is Python-version-dependent: a bare
        # KeyboardInterrupt on 3.12/3.13, but asyncio.CancelledError on 3.10.
        # Catch both and exit clean like the sibling fleet MCP servers.
        os._exit(0)


if __name__ == "__main__":
    main()
