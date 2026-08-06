"""Entry point for cloudarmor-mcp."""

import argparse
import asyncio
import os
import sys

from cloudarmor_mcp import __version__


def main():
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
