"""
Multi-Agent Authentication Defence System
==========================================
Main runner. Processes a batch of authentication requests through the
multi-agent coordination pipeline.

Architecture:
  - Coordinator orchestrates specialist agents
  - Each specialist analyses one dimension (token validity, behaviour, etc.)
  - Coordinator synthesises findings and makes the final disposition decision
  - All findings, reasoning, and decisions are logged in immutable audit trail

Usage:
    python3 run.py                  # Process all sample requests
    python3 run.py --request REQ-001 # Process a specific scenario
    python3 run.py --json           # Output raw JSON instead of formatted display
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from agents.token_validator import TokenValidatorAgent
from agents.behavioral_analyst import BehavioralAnalystAgent
from coordinator import CoordinatorAgent
from tokens import SAMPLE_REQUESTS

AUDIT_DIR = Path(__file__).parent / "audit"
AUDIT_DIR.mkdir(exist_ok=True)
AUDIT_LOG = AUDIT_DIR / "decisions.jsonl"


# ===== Terminal styling =====
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"


def banner(text, c=C.CYAN):
    print(f"\n{c}{C.BOLD}{'=' * 78}\n{text}\n{'=' * 78}{C.RESET}")


def severity_color(s):
    return {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}.get(s, C.DIM)


def disposition_color(d):
    return {
        "allow": C.GREEN,
        "monitor": C.BLUE,
        "challenge": C.YELLOW,
        "revoke": C.RED,
    }.get(d, C.DIM)


def render_decision(result):
    """Pretty-print a single coordinator decision."""
    req_id = result["request_id"]
    scenario = result["scenario_name"]
    decision = result["decision"]
    synthesis = result["synthesis"]

    banner(f"REQUEST {req_id}: {scenario}", C.CYAN)

    # Show what each specialist found
    print(f"\n  {C.BOLD}Specialist Agent Findings:{C.RESET}")
    for sf in result["specialist_findings"]:
        agent = sf["agent"]
        risk = sf["risk_score"]
        conf = sf["confidence"]
        rec = sf["recommended_disposition"]
        rec_color = disposition_color(rec)

        print(f"\n  {C.BOLD}{agent}{C.RESET} (confidence: {conf:.2f})")
        print(f"    Risk score:    {risk}/100")
        print(f"    Recommends:    {rec_color}{rec.upper()}{C.RESET}")
        print(f"    {C.DIM}Reasoning: {sf['reasoning']}{C.RESET}")

        if sf["findings"]:
            print(f"    Findings:")
            for f in sf["findings"]:
                sev = severity_color(f["severity"])
                print(f"      {sev}[{f['severity']}]{C.RESET} {f['issue']}: {C.DIM}{f['detail']}{C.RESET}")

    # Coordinator synthesis
    print(f"\n  {C.MAGENTA}{C.BOLD}Coordinator Synthesis:{C.RESET}")
    print(f"    Weighted risk score:       {synthesis['weighted_risk_score']}/100")
    print(f"    Max severity:              {severity_color(synthesis['max_severity'])}{synthesis['max_severity']}{C.RESET}")
    print(f"    Total findings:            {len(synthesis['all_findings'])}")
    print(f"    Specialist recommendations: {synthesis['specialist_recommendations']}")

    # Final decision
    disp = decision["disposition"]
    disp_color = disposition_color(disp)
    print(f"\n  {C.BOLD}FINAL DECISION:{C.RESET} {disp_color}{C.BOLD}{disp.upper()}{C.RESET}")
    if decision["requires_human_review"]:
        print(f"  {C.YELLOW}{C.BOLD}>> HUMAN REVIEW REQUIRED <<{C.RESET}")
    print(f"  {C.DIM}{decision['rationale']}{C.RESET}")


def write_audit(result):
    """Write decision to immutable audit log (hashed values where appropriate)."""
    audit_entry = {
        "timestamp": result["timestamp"],
        "request_id": result["request_id"],
        "scenario_name": result["scenario_name"],
        "specialist_findings": result["specialist_findings"],
        "synthesis": {
            "weighted_risk_score": result["synthesis"]["weighted_risk_score"],
            "max_severity": result["synthesis"]["max_severity"],
            "finding_count": len(result["synthesis"]["all_findings"]),
            "specialist_recommendations": result["synthesis"]["specialist_recommendations"],
        },
        "decision": result["decision"],
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")


def render_summary(results):
    """Show overall summary across all processed requests."""
    banner("EXECUTION SUMMARY", C.MAGENTA)

    total = len(results)
    by_disposition = {}
    by_expected = {"correct": 0, "incorrect": 0, "no_expectation": 0}
    human_review_count = 0

    for r in results:
        disp = r["decision"]["disposition"]
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        if r["decision"]["requires_human_review"]:
            human_review_count += 1

    print(f"\n  Total requests processed: {total}")
    print(f"\n  {C.BOLD}Dispositions:{C.RESET}")
    for disp in ["allow", "monitor", "challenge", "revoke"]:
        count = by_disposition.get(disp, 0)
        if count:
            color = disposition_color(disp)
            print(f"    {color}{disp:10}{C.RESET} {count}")

    if human_review_count:
        print(f"\n  {C.YELLOW}Human review queue: {human_review_count} request(s){C.RESET}")

    print(f"\n  {C.DIM}Audit log: {AUDIT_LOG}{C.RESET}")


def main():
    parser = argparse.ArgumentParser(description="Multi-Agent Authentication Defence System")
    parser.add_argument("--request", help="Process a specific request ID only")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    parser.add_argument("--reset", action="store_true", help="Clear audit log")
    args = parser.parse_args()

    if args.reset:
        if AUDIT_LOG.exists():
            AUDIT_LOG.unlink()
        print(f"{C.GREEN}Audit log reset.{C.RESET}")
        return

    # Initialise the multi-agent system
    specialists = [
        TokenValidatorAgent(),
        BehavioralAnalystAgent(),
    ]
    coordinator = CoordinatorAgent(specialists=specialists)

    # Filter requests if specific one requested
    requests = SAMPLE_REQUESTS
    if args.request:
        requests = [r for r in requests if r["request_id"] == args.request]
        if not requests:
            print(f"{C.RED}No request found with ID: {args.request}{C.RESET}")
            return

    if not args.json:
        banner("MULTI-AGENT AUTHENTICATION DEFENCE SYSTEM", C.MAGENTA)
        print(f"  Coordinator: {coordinator.AGENT_NAME}")
        print(f"  Specialists: {', '.join(s.AGENT_NAME for s in specialists)}")
        print(f"  Requests to process: {len(requests)}")

    # Process each request
    results = []
    for req in requests:
        result = coordinator.process(req)
        results.append(result)
        write_audit(result)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            render_decision(result)

    if not args.json:
        render_summary(results)


if __name__ == "__main__":
    main()
