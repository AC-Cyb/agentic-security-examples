"""
Simulated Environment
======================
Mock identity provider, session store, and SOC notifier.
This file pretends to be your real systems - it never actually does anything destructive.

In production this would be replaced by real connectors:
- IdP: Okta API, Azure AD, AWS IAM
- Sessions: Redis session store, Okta session API
- SOC: Slack webhook, ServiceNow API, PagerDuty
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

STATE_DIR = Path(__file__).parent / "state"
STATE_DIR.mkdir(exist_ok=True)
AUDIT_DIR = Path(__file__).parent / "audit"
AUDIT_DIR.mkdir(exist_ok=True)

USERS_FILE = STATE_DIR / "users.json"
SESSIONS_FILE = STATE_DIR / "sessions.json"
SOC_INBOX_FILE = STATE_DIR / "soc_inbox.json"
AUDIT_LOG_FILE = AUDIT_DIR / "audit.jsonl"


def init_state():
    """Initialise simulated environment state on first run."""
    if not USERS_FILE.exists():
        users = {
            "jsmith": {
                "email": "[email protected]",
                "department": "Finance",
                "role": "Senior Analyst",
                "status": "active",
                "password_last_changed": "2025-12-15",
                "mfa_enabled": True,
                "is_admin": False,
            },
            "kchen": {
                "email": "[email protected]",
                "department": "Engineering",
                "role": "Software Engineer",
                "status": "active",
                "password_last_changed": "2025-11-02",
                "mfa_enabled": True,
                "is_admin": False,
            },
            "rgarcia": {
                "email": "[email protected]",
                "department": "Operations",
                "role": "Operations Manager",
                "status": "active",
                "password_last_changed": "2026-02-10",
                "mfa_enabled": False,
                "is_admin": False,
            },
            "admin_svc": {
                "email": "[email protected]",
                "department": "Platform",
                "role": "Service Account",
                "status": "active",
                "password_last_changed": "2025-08-01",
                "mfa_enabled": False,
                "is_admin": True,
            },
        }
        USERS_FILE.write_text(json.dumps(users, indent=2))

    if not SESSIONS_FILE.exists():
        now = datetime.now()
        sessions = {
            "sess_a1b2c3": {"user": "jsmith", "ip": "10.0.1.45", "started": (now - timedelta(hours=2)).isoformat(), "device": "MacBook Pro - jsmith", "active": True},
            "sess_d4e5f6": {"user": "jsmith", "ip": "185.220.101.45", "started": (now - timedelta(minutes=12)).isoformat(), "device": "Unknown - Linux", "active": True},
            "sess_g7h8i9": {"user": "kchen", "ip": "10.0.2.137", "started": (now - timedelta(hours=5)).isoformat(), "device": "MacBook Pro - kchen", "active": True},
            "sess_j0k1l2": {"user": "kchen", "ip": "194.165.16.118", "started": (now - timedelta(minutes=30)).isoformat(), "device": "Unknown - Headless", "active": True},
            "sess_m3n4o5": {"user": "rgarcia", "ip": "10.0.3.89", "started": (now - timedelta(hours=1)).isoformat(), "device": "iPhone - rgarcia", "active": True},
        }
        SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))

    if not SOC_INBOX_FILE.exists():
        SOC_INBOX_FILE.write_text(json.dumps([], indent=2))


def get_user(username):
    users = json.loads(USERS_FILE.read_text())
    return users.get(username)


def get_user_sessions(username):
    sessions = json.loads(SESSIONS_FILE.read_text())
    return {sid: s for sid, s in sessions.items() if s["user"] == username and s["active"]}


def get_all_active_sessions():
    sessions = json.loads(SESSIONS_FILE.read_text())
    return {sid: s for sid, s in sessions.items() if s["active"]}


# === REMEDIATION ACTIONS (simulated) ===

def revoke_session(session_id, reason):
    """Mark a session as revoked. Returns success status."""
    time.sleep(0.3)  # simulate API latency
    sessions = json.loads(SESSIONS_FILE.read_text())
    if session_id not in sessions:
        return {"success": False, "error": f"Session {session_id} not found"}
    if not sessions[session_id]["active"]:
        return {"success": False, "error": f"Session {session_id} already revoked"}
    sessions[session_id]["active"] = False
    sessions[session_id]["revoked_at"] = datetime.now().isoformat()
    sessions[session_id]["revoked_reason"] = reason
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))
    return {"success": True, "session_id": session_id, "user": sessions[session_id]["user"], "ip": sessions[session_id]["ip"]}


def force_password_reset(username, reason):
    """Mark user account as requiring password reset on next login."""
    time.sleep(0.3)
    users = json.loads(USERS_FILE.read_text())
    if username not in users:
        return {"success": False, "error": f"User {username} not found"}
    users[username]["password_reset_required"] = True
    users[username]["password_reset_initiated_at"] = datetime.now().isoformat()
    users[username]["password_reset_reason"] = reason
    USERS_FILE.write_text(json.dumps(users, indent=2))
    return {"success": True, "username": username, "email": users[username]["email"]}


def notify_soc(severity, title, details, recommended_action, finding_id):
    """Send a notification to the SOC inbox."""
    time.sleep(0.2)
    inbox = json.loads(SOC_INBOX_FILE.read_text())
    notification = {
        "id": f"SOC-{int(time.time()*1000)}",
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "title": title,
        "details": details,
        "recommended_action": recommended_action,
        "finding_id": finding_id,
        "status": "open"
    }
    inbox.append(notification)
    SOC_INBOX_FILE.write_text(json.dumps(inbox, indent=2))
    return {"success": True, "notification_id": notification["id"]}


# === AUDIT TRAIL ===

def audit_log(event):
    """Append an audit event - timestamped, immutable record of every agent decision."""
    event["timestamp"] = datetime.now().isoformat()
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def reset_environment():
    """Wipe state and reinitialise - useful for testing."""
    for f in [USERS_FILE, SESSIONS_FILE, SOC_INBOX_FILE, AUDIT_LOG_FILE]:
        if f.exists():
            f.unlink()
    init_state()
