"""
Review tool - inspect the state of the simulated environment after agent runs.
Shows what changed, what notifications went to SOC, and the audit trail.
"""

import json
from pathlib import Path
import environment as env


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


def banner(text, c=C.CYAN):
    print(f"\n{c}{C.BOLD}{'=' * 70}\n{text}\n{'=' * 70}{C.RESET}")


def review():
    banner("ENVIRONMENT STATE REVIEW", C.MAGENTA)

    # Sessions
    print(f"\n{C.BOLD}ACTIVE SESSIONS:{C.RESET}")
    if env.SESSIONS_FILE.exists():
        sessions = json.loads(env.SESSIONS_FILE.read_text())
        active = {s: d for s, d in sessions.items() if d["active"]}
        revoked = {s: d for s, d in sessions.items() if not d["active"]}
        if active:
            for sid, s in active.items():
                print(f"  {C.GREEN}[ACTIVE]{C.RESET}   {sid} | user={s['user']:10} | ip={s['ip']:16} | device={s['device']}")
        else:
            print(f"  {C.DIM}(no active sessions){C.RESET}")
        if revoked:
            print(f"\n{C.BOLD}REVOKED SESSIONS:{C.RESET}")
            for sid, s in revoked.items():
                print(f"  {C.RED}[REVOKED]{C.RESET}  {sid} | user={s['user']:10} | ip={s['ip']:16}")
                print(f"           {C.DIM}Reason: {s.get('revoked_reason', 'n/a')}{C.RESET}")

    # User accounts with reset required
    print(f"\n{C.BOLD}USER ACCOUNT STATUS:{C.RESET}")
    if env.USERS_FILE.exists():
        users = json.loads(env.USERS_FILE.read_text())
        for username, u in users.items():
            reset_flag = ""
            if u.get("password_reset_required"):
                reset_flag = f" {C.YELLOW}[PASSWORD RESET REQUIRED]{C.RESET}"
            mfa = "MFA enabled" if u["mfa_enabled"] else f"{C.YELLOW}MFA disabled{C.RESET}"
            print(f"  {username:12} | {u['role']:25} | {mfa}{reset_flag}")
            if u.get("password_reset_reason"):
                print(f"               {C.DIM}Reset reason: {u['password_reset_reason']}{C.RESET}")

    # SOC inbox
    print(f"\n{C.BOLD}SOC INBOX:{C.RESET}")
    if env.SOC_INBOX_FILE.exists():
        inbox = json.loads(env.SOC_INBOX_FILE.read_text())
        if not inbox:
            print(f"  {C.DIM}(no notifications){C.RESET}")
        else:
            for n in inbox:
                sev_colour = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}.get(n["severity"], "")
                print(f"  {sev_colour}[{n['severity'].upper()}]{C.RESET} {n['id']} - {n['title']}")
                print(f"         {C.DIM}{n['recommended_action']}{C.RESET}")

    # Audit trail summary
    print(f"\n{C.BOLD}AUDIT TRAIL:{C.RESET}")
    if env.AUDIT_LOG_FILE.exists():
        events = []
        with open(env.AUDIT_LOG_FILE) as f:
            for line in f:
                events.append(json.loads(line))
        print(f"  Total events: {len(events)}")
        from collections import Counter
        event_types = Counter(e["event"] for e in events)
        for et, count in event_types.most_common():
            print(f"    {et}: {count}")
        print(f"\n  {C.DIM}Full audit log: {env.AUDIT_LOG_FILE}{C.RESET}")

    print()


if __name__ == "__main__":
    review()
