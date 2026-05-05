"""
SOC Discovery View
==================
The operational interface for the SOC team. Shows every vaulted secret with
its location, owner, severity, and rotation status.

In production this would be a web dashboard. Here it's a terminal report -
same information, simpler infrastructure.

Usage:
    python3 soc_view.py                    # Full registry view
    python3 soc_view.py --severity Critical # Filter by severity
    python3 soc_view.py --owner billing     # Filter by team
    python3 soc_view.py --status pending    # Filter by rotation status
    python3 soc_view.py --json              # Machine-readable JSON output
"""

import sys
import json
import argparse
from collections import Counter
from datetime import datetime
import registry


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"


def severity_colour(s):
    return {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}.get(s, "")


def status_indicator(status):
    indicators = {
        "pending": f"{C.YELLOW}⊙ pending{C.RESET}",
        "scheduled": f"{C.BLUE}◐ scheduled{C.RESET}",
        "rotated": f"{C.GREEN}● rotated{C.RESET}",
        "failed": f"{C.RED}✗ failed{C.RESET}",
    }
    return indicators.get(status, status)


def banner(text):
    print(f"\n{C.MAGENTA}{C.BOLD}{'=' * 80}\n{text}\n{'=' * 80}{C.RESET}")


def render_summary(secrets):
    if not secrets:
        return
    print(f"\n{C.BOLD}SUMMARY{C.RESET}")
    print(f"  Total secrets in registry: {C.BOLD}{len(secrets)}{C.RESET}")

    sev_counts = Counter(s["severity"] for s in secrets)
    print(f"\n  By Severity:")
    for sev in ["Critical", "High", "Medium", "Low"]:
        if sev_counts.get(sev):
            colour = severity_colour(sev)
            print(f"    {colour}{C.BOLD}{sev:10}{C.RESET} {sev_counts[sev]}")

    cat_counts = Counter(s["category"] for s in secrets)
    print(f"\n  By Category:")
    for cat, count in cat_counts.most_common():
        print(f"    {cat:10} {count}")

    owner_counts = Counter(s["owner_team"] for s in secrets)
    print(f"\n  By Owner Team:")
    for owner, count in owner_counts.most_common():
        print(f"    {owner:20} {count}")

    status_counts = Counter(s["rotation_status"] for s in secrets)
    print(f"\n  By Rotation Status:")
    for status, count in status_counts.most_common():
        print(f"    {status_indicator(status):30} {count}")


def render_table(secrets):
    if not secrets:
        print(f"\n{C.DIM}No secrets match this query.{C.RESET}")
        return

    print(f"\n{C.BOLD}REGISTRY ENTRIES{C.RESET}")
    print(f"{C.DIM}{'-' * 80}{C.RESET}")

    # Sort: critical first, then by discovered_at descending
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    secrets = sorted(secrets, key=lambda s: (sev_order.get(s["severity"], 9), -datetime.fromisoformat(s["discovered_at"]).timestamp()))

    for i, s in enumerate(secrets, 1):
        colour = severity_colour(s["severity"])
        print(f"\n{C.BOLD}[{i}] {s['secret_id']}{C.RESET}")
        print(f"    {colour}{C.BOLD}{s['severity']:10}{C.RESET} {s['description']}")
        print(f"    {C.DIM}Type:{C.RESET}      {s['secret_type']} ({s['category']})")
        print(f"    {C.DIM}Vault URI:{C.RESET} {C.CYAN}{s['vault_uri']}#{s['current_version']}{C.RESET}")
        print(f"    {C.DIM}Found in:{C.RESET}  {s['discovered_in']['file']} line {s['discovered_in']['line']}")
        print(f"    {C.DIM}Owner:{C.RESET}     {s['owner_team']}")
        print(f"    {C.DIM}Status:{C.RESET}    {status_indicator(s['rotation_status'])}")
        print(f"    {C.DIM}Reg:{C.RESET}       {', '.join(s['regulatory'])}")
        if s.get("last_seen_at"):
            print(f"    {C.DIM}Last seen:{C.RESET} {s['last_seen_at']} (sightings: {s.get('sightings', 1)})")

    print()


def render_json(secrets):
    print(json.dumps({
        "count": len(secrets),
        "secrets": secrets,
    }, indent=2))


def main():
    p = argparse.ArgumentParser(description="SOC Secret Registry View")
    p.add_argument("--severity", help="Filter by severity (Critical/High/Medium/Low)")
    p.add_argument("--owner", help="Filter by owner team")
    p.add_argument("--status", help="Filter by rotation status (pending/scheduled/rotated/failed)")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("--summary-only", action="store_true", help="Show summary stats only")
    args = p.parse_args()

    secrets = registry.list_all()

    # Apply filters
    if args.severity:
        secrets = [s for s in secrets if s["severity"].lower() == args.severity.lower()]
    if args.owner:
        secrets = [s for s in secrets if s["owner_team"].lower() == args.owner.lower()]
    if args.status:
        secrets = [s for s in secrets if s["rotation_status"].lower() == args.status.lower()]

    if args.json:
        render_json(secrets)
        return

    banner("SECRET REGISTRY - SOC OPERATIONAL VIEW")

    filters_applied = []
    if args.severity: filters_applied.append(f"severity={args.severity}")
    if args.owner:    filters_applied.append(f"owner={args.owner}")
    if args.status:   filters_applied.append(f"status={args.status}")
    if filters_applied:
        print(f"  {C.DIM}Filters: {', '.join(filters_applied)}{C.RESET}")

    if not secrets:
        print(f"\n  {C.DIM}No secrets in registry. Run agent.py to discover and vault secrets.{C.RESET}")
        return

    render_summary(secrets)

    if not args.summary_only:
        render_table(secrets)


if __name__ == "__main__":
    main()
