"""
Secret Registry
================
The discoverable index that maps every secret reference to its location, owner,
severity, and lifecycle metadata. This is what the SOC team uses to know what
exists, where it lives, and what state it's in.

In production this would be:
  - Backed by a database (DynamoDB, Postgres) for queryability
  - Exposed via an API for the SOC tooling to integrate with
  - Synced with ServiceNow CMDB for asset management
  - Tied into rotation schedulers and alerting

Here it's a JSON file - same data shape, simpler infrastructure.
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

REGISTRY_FILE = Path(__file__).parent / "registry" / "secret_registry.json"
REGISTRY_FILE.parent.mkdir(exist_ok=True)


def _load():
    if REGISTRY_FILE.exists():
        return json.loads(REGISTRY_FILE.read_text())
    return {"secrets": [], "metadata": {"last_updated": None}}


def _save(data):
    data["metadata"]["last_updated"] = datetime.now().isoformat()
    REGISTRY_FILE.write_text(json.dumps(data, indent=2))


def derive_secret_id(secret_type, file_name, line_number, matched_text):
    """Generate a stable secret ID. Same input -> same ID (idempotency)."""
    raw = f"{secret_type}:{file_name}:{line_number}:{matched_text}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:12]
    return f"sec_{h}"


def derive_owner_team(file_name):
    """
    Heuristic to derive owning team from file context.

    In production: look up CODEOWNERS, ServiceNow CMDB, or service registry.
    Here: simple file-name-based heuristic for demonstration.
    """
    file_lower = file_name.lower()
    if "billing" in file_lower or "payment" in file_lower:
        return "billing"
    if "auth" in file_lower:
        return "platform-iam"
    if "debug" in file_lower:
        return "engineering"
    if "access" in file_lower:
        return "platform-infra"
    if "application" in file_lower or "app" in file_lower:
        return "application-team"
    return "unassigned"


def register_secret(secret_id, vault_uri, version, finding):
    """
    Register a vaulted secret in the discovery index.

    The registry NEVER stores the actual secret value - only metadata.
    This file is safe to share, query, and replicate.
    """
    registry = _load()

    # Check if already registered (idempotency)
    existing = next((s for s in registry["secrets"] if s["secret_id"] == secret_id), None)
    if existing:
        # Update the version reference and re-register timestamp
        existing["current_version"] = version
        existing["last_seen_at"] = datetime.now().isoformat()
        existing["sightings"] = existing.get("sightings", 1) + 1
        _save(registry)
        return existing

    entry = {
        "secret_id": secret_id,
        "vault_uri": vault_uri,
        "current_version": version,
        "secret_type": finding["pattern_name"],
        "category": finding["category"],
        "severity": finding["severity"],
        "description": finding["description"],
        "regulatory": finding["regulatory"],
        "discovered_in": {
            "file": finding["file"],
            "line": finding["line_number"],
        },
        "discovered_at": datetime.now().isoformat(),
        "discovered_by": "secrets-agent v2",
        "owner_team": derive_owner_team(finding["file"]),
        "rotation_status": "pending",  # pending | scheduled | rotated | failed
        "rotation_target_date": (datetime.now() + timedelta(days=7)).isoformat(),
        "last_rotated_at": None,
        "last_seen_at": datetime.now().isoformat(),
        "sightings": 1,
        "ai_confidence": finding.get("ai_confidence"),
        "tags": {
            "auto_discovered": "true",
            "needs_review": "true" if finding["severity"] in ["Critical", "High"] else "false",
        }
    }

    registry["secrets"].append(entry)
    _save(registry)
    return entry


def list_all():
    return _load()["secrets"]


def query_by_severity(severity):
    return [s for s in _load()["secrets"] if s["severity"] == severity]


def query_by_owner(team):
    return [s for s in _load()["secrets"] if s["owner_team"] == team]


def query_by_status(status):
    return [s for s in _load()["secrets"] if s["rotation_status"] == status]


def reset_registry():
    if REGISTRY_FILE.exists():
        REGISTRY_FILE.unlink()
