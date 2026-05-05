"""
Authentication Remediation Agent
=================================
A tiered-autonomy agent that responds to authentication findings:
  - Auto-remediates low-risk events
  - Requests human approval for high-risk events
  - Maintains a full audit trail of every decision

This is the agentic security model in code:
  Detect (input from findings)  ->  Decide (policy + risk)  ->  Act (with appropriate oversight)  ->  Log (audit trail)

Usage:
    python3 agent.py                  # Interactive mode - prompts for approvals
    python3 agent.py --auto-approve   # Approve all (testing only - never use in production)
    python3 agent.py --dry-run        # Show what it WOULD do without acting
    python3 agent.py --reset          # Reset simulated environment
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

import environment as env
from findings import SAMPLE_FINDINGS


# === ANSI COLOURS for readability ===
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
    WHITE = "\033[97m"


def banner(text, colour=C.CYAN):
    print(f"\n{colour}{C.BOLD}{'=' * 70}")
    print(f"{text}")
    print(f"{'=' * 70}{C.RESET}")


def severity_badge(severity):
    colours = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}
    c = colours.get(severity, C.WHITE)
    return f"{c}{C.BOLD}[{severity.upper()}]{C.RESET}"


# === POLICY: tiered autonomy decisions ===

class RemediationPolicy:
    """
    The decision policy: what action(s) to take and whether human approval is required.

    Design principle: actions get more autonomous as risk decreases.
    Critical = always require approval (irreversible, high-impact).
    Low = auto-remediate (reversible, low-impact, high-confidence).
    """

    @staticmethod
    def evaluate(finding):
        severity = finding["severity"]
        finding_type = finding["type"]
        ip_reputation = finding.get("ip_reputation", "unknown")

        actions = []

        # === CRITICAL: account compromise indicators ===
        if severity == "Critical":
            actions = [
                {
                    "action": "revoke_session",
                    "params": {"session_id": finding["session_id"]},
                    "approval_required": False,  # immediate auto-revoke
                    "rationale": "Suspicious session must be terminated immediately to prevent further attacker access. This action is reversible (user can re-authenticate)."
                },
                {
                    "action": "force_password_reset",
                    "params": {"username": finding["username"]},
                    "approval_required": True,  # impacts user experience
                    "rationale": "User credentials likely compromised. Forcing password reset prevents re-use of stolen credentials. Requires approval because it disrupts the user."
                },
                {
                    "action": "notify_soc",
                    "params": {
                        "severity": "Critical",
                        "title": finding["title"],
                        "recommended_action": "Engage incident response team immediately. Initiate forensic investigation under attorney-client privilege."
                    },
                    "approval_required": False,
                    "rationale": "SOC must be informed of all critical events for situational awareness and human investigation."
                },
            ]

        # === HIGH: strong indicators but ambiguity remains ===
        elif severity == "High":
            actions = [
                {
                    "action": "revoke_session",
                    "params": {"session_id": finding["session_id"]},
                    "approval_required": True,  # high but not certain - confirm with human
                    "rationale": "Strong indicators of compromise but some ambiguity. Session revocation recommended but requires human review of context."
                },
                {
                    "action": "notify_soc",
                    "params": {
                        "severity": "High",
                        "title": finding["title"],
                        "recommended_action": "Investigate session and user activity. Confirm whether compromise has occurred."
                    },
                    "approval_required": False,
                    "rationale": "SOC notification is non-disruptive and always appropriate for high-severity events."
                },
            ]

        # === MEDIUM: anomalous but not necessarily malicious ===
        elif severity == "Medium":
            actions = [
                {
                    "action": "notify_soc",
                    "params": {
                        "severity": "Medium",
                        "title": finding["title"],
                        "recommended_action": "Review user activity. Consider reaching out to user to verify legitimate access."
                    },
                    "approval_required": False,
                    "rationale": "Medium-severity anomalies warrant SOC review but rarely justify automated disruption of the user."
                },
            ]

        # === LOW: hygiene / best practice issues ===
        elif severity == "Low":
            if finding_type == "stale_password_low_risk_alert":
                actions = [
                    {
                        "action": "force_password_reset",
                        "params": {"username": finding["username"]},
                        "approval_required": False,  # auto-remediate hygiene issues
                        "rationale": "Stale credential rotation is a routine hygiene action. Low disruption, high security benefit, fully reversible. Safe to auto-remediate."
                    },
                    {
                        "action": "notify_soc",
                        "params": {
                            "severity": "Low",
                            "title": "Auto-remediated: " + finding["title"],
                            "recommended_action": "No action required - automated rotation initiated."
                        },
                        "approval_required": False,
                        "rationale": "Informational notification only - SOC awareness of automated action."
                    },
                ]

        return actions


# === EXECUTION ENGINE ===

class RemediationAgent:
    def __init__(self, auto_approve=False, dry_run=False):
        self.auto_approve = auto_approve
        self.dry_run = dry_run
        self.stats = {"executed": 0, "approved": 0, "rejected": 0, "auto_actions": 0, "dry_run_actions": 0}

    def request_approval(self, finding, action):
        """Request human approval for an action."""
        if self.dry_run:
            print(f"  {C.MAGENTA}[DRY-RUN APPROVAL]{C.RESET} Would prompt for approval - simulating approval")
            return True

        if self.auto_approve:
            print(f"  {C.YELLOW}[AUTO-APPROVED]{C.RESET} {action['action']} - testing mode")
            return True

        print(f"\n  {C.YELLOW}{C.BOLD}[APPROVAL REQUIRED]{C.RESET}")
        print(f"  Action:    {C.BOLD}{action['action']}{C.RESET}")
        print(f"  Target:    {action['params']}")
        print(f"  Rationale: {C.DIM}{action['rationale']}{C.RESET}")
        try:
            response = input(f"\n  Approve? [y/N]: ").strip().lower()
        except EOFError:
            print(f"  {C.DIM}(no input available - rejecting by default){C.RESET}")
            return False
        return response == "y"

    def execute_action(self, finding, action):
        """Execute a single action with full audit trail."""
        action_name = action["action"]
        params = action["params"]

        # Augment params with finding context for the audit trail
        full_reason = f"[{finding['id']}] {finding['title']}"

        if self.dry_run:
            print(f"  {C.MAGENTA}[DRY RUN]{C.RESET} Would execute {C.BOLD}{action_name}{C.RESET} with {params}")
            self.stats["dry_run_actions"] += 1
            env.audit_log({
                "event": "dry_run",
                "finding_id": finding["id"],
                "action": action_name,
                "params": params,
                "decision": "would_execute"
            })
            return

        result = None
        if action_name == "revoke_session":
            result = env.revoke_session(params["session_id"], reason=full_reason)
        elif action_name == "force_password_reset":
            result = env.force_password_reset(params["username"], reason=full_reason)
        elif action_name == "notify_soc":
            result = env.notify_soc(
                severity=params["severity"],
                title=params["title"],
                details=finding["description"],
                recommended_action=params["recommended_action"],
                finding_id=finding["id"]
            )
        else:
            result = {"success": False, "error": f"Unknown action: {action_name}"}

        if result and result.get("success"):
            print(f"  {C.GREEN}[OK]{C.RESET} {action_name} executed successfully")
            self.stats["executed"] += 1
        else:
            err = result.get("error", "unknown error") if result else "no result"
            print(f"  {C.RED}[FAIL]{C.RESET} {action_name}: {err}")

        env.audit_log({
            "event": "action_executed",
            "finding_id": finding["id"],
            "action": action_name,
            "params": params,
            "rationale": action["rationale"],
            "approval_required": action["approval_required"],
            "result": result
        })

    def process_finding(self, finding):
        """Process a single finding through the policy and execution pipeline."""
        banner(f"FINDING {finding['id']}: {finding['title']}", C.CYAN)
        print(f"  Severity:  {severity_badge(finding['severity'])}")
        print(f"  Type:      {finding['type']}")
        print(f"  User:      {finding['username']}")
        print(f"  Source IP: {finding['source_ip']} ({finding['ip_reputation']})")
        print(f"  Context:   {C.DIM}{finding['ip_context']}{C.RESET}")
        print(f"\n  Description: {finding['description']}")
        print(f"\n  Evidence:")
        for e in finding["evidence"]:
            print(f"    - {e}")

        # Get the policy decision
        actions = RemediationPolicy.evaluate(finding)
        if not actions:
            print(f"\n  {C.DIM}Policy: no automated actions configured for this finding type.{C.RESET}")
            return

        print(f"\n  {C.BOLD}Policy decision: {len(actions)} action(s) recommended{C.RESET}")

        env.audit_log({
            "event": "finding_received",
            "finding_id": finding["id"],
            "severity": finding["severity"],
            "type": finding["type"],
            "actions_proposed": [a["action"] for a in actions]
        })

        # Execute each action
        for i, action in enumerate(actions, 1):
            print(f"\n  {C.BOLD}Action {i}/{len(actions)}: {action['action']}{C.RESET}")

            if action["approval_required"]:
                approved = self.request_approval(finding, action)
                if not approved:
                    print(f"  {C.RED}[REJECTED]{C.RESET} Action skipped by human reviewer")
                    self.stats["rejected"] += 1
                    env.audit_log({
                        "event": "action_rejected",
                        "finding_id": finding["id"],
                        "action": action["action"],
                        "decision": "human_rejected"
                    })
                    continue
                self.stats["approved"] += 1
            else:
                print(f"  {C.GREEN}[AUTO]{C.RESET} {C.DIM}{action['rationale']}{C.RESET}")
                self.stats["auto_actions"] += 1

            self.execute_action(finding, action)

    def run(self, findings):
        banner("AUTHENTICATION REMEDIATION AGENT", C.MAGENTA)
        mode = "DRY RUN" if self.dry_run else ("AUTO-APPROVE" if self.auto_approve else "INTERACTIVE")
        print(f"  Mode: {C.BOLD}{mode}{C.RESET}")
        print(f"  Findings to process: {len(findings)}")

        for finding in findings:
            self.process_finding(finding)

        # Summary
        banner("EXECUTION SUMMARY", C.MAGENTA)
        print(f"  Findings processed:    {len(findings)}")
        print(f"  Auto-executed actions: {self.stats['auto_actions']}")
        print(f"  Approved actions:      {self.stats['approved']}")
        print(f"  Rejected actions:      {self.stats['rejected']}")
        if self.dry_run:
            print(f"  Dry-run actions:       {self.stats['dry_run_actions']}")
        else:
            print(f"  Successfully executed: {self.stats['executed']}")
        print(f"\n  {C.DIM}Audit log: {env.AUDIT_LOG_FILE}{C.RESET}")
        print(f"  {C.DIM}SOC inbox: {env.SOC_INBOX_FILE}{C.RESET}")
        print(f"  {C.DIM}Run 'python3 review.py' to see the post-action environment state.{C.RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Authentication Remediation Agent")
    parser.add_argument("--auto-approve", action="store_true", help="Auto-approve all actions (testing only)")
    parser.add_argument("--dry-run", action="store_true", help="Log what would be done without acting")
    parser.add_argument("--reset", action="store_true", help="Reset simulated environment state")
    args = parser.parse_args()

    if args.reset:
        env.reset_environment()
        print(f"{C.GREEN}Environment reset.{C.RESET}")
        return

    env.init_state()
    agent = RemediationAgent(auto_approve=args.auto_approve, dry_run=args.dry_run)
    agent.run(SAMPLE_FINDINGS)


if __name__ == "__main__":
    main()
