"""
Vault Module
============
Simulates AWS Secrets Manager for the reference implementation.

In production, replace these functions with boto3 calls to real AWS Secrets Manager:
  - put_secret() -> secrets_client.create_secret() or update_secret()
  - get_secret() -> secrets_client.get_secret_value()
  - rotate_secret() -> secrets_client.rotate_secret()

The interface stays identical. Only the backend changes.

Why this design:
  - Agent code is vault-agnostic - swap AWS for HashiCorp Vault, Azure Key Vault, etc.
  - Easy to test without real cloud credentials
  - Demonstrates the pattern that matters: vault as a swappable adapter
"""

import json
import time
import hashlib
from datetime import datetime
from pathlib import Path

VAULT_FILE = Path(__file__).parent / "vault_state" / "secrets.json"
VAULT_FILE.parent.mkdir(exist_ok=True)


def _load():
    if VAULT_FILE.exists():
        return json.loads(VAULT_FILE.read_text())
    return {}


def _save(data):
    VAULT_FILE.write_text(json.dumps(data, indent=2))


def put_secret(path, value, tags=None):
    """
    Store a secret in the vault. Returns the URI and version.

    Production equivalent:
        client = boto3.client('secretsmanager')
        response = client.create_secret(
            Name=path,
            SecretString=value,
            Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
        )
        return f"secret://aws-secretsmanager/{path}", response['VersionId']
    """
    time.sleep(0.05)  # simulate API latency
    vault = _load()

    if path in vault:
        # Versioning - keep history
        existing = vault[path]
        existing["versions"].append({
            "version": f"v{len(existing['versions']) + 1}",
            "value": value,
            "stored_at": datetime.now().isoformat(),
            "stored_by": "secrets-agent",
        })
        existing["current_version"] = existing["versions"][-1]["version"]
        existing["updated_at"] = datetime.now().isoformat()
    else:
        vault[path] = {
            "path": path,
            "current_version": "v1",
            "versions": [{
                "version": "v1",
                "value": value,
                "stored_at": datetime.now().isoformat(),
                "stored_by": "secrets-agent",
            }],
            "tags": tags or {},
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }

    _save(vault)

    uri = f"secret://aws-secretsmanager/{path}"
    version = vault[path]["current_version"]
    return uri, version


def get_secret(path, version=None):
    """
    Retrieve a secret from the vault by path and optional version.

    Production equivalent:
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId=path, VersionStage=version)
        return response['SecretString']
    """
    time.sleep(0.03)
    vault = _load()
    if path not in vault:
        raise KeyError(f"Secret not found: {path}")

    secret = vault[path]
    target_version = version or secret["current_version"]
    for v in secret["versions"]:
        if v["version"] == target_version:
            # Audit access
            _audit_access(path, target_version)
            return v["value"]
    raise KeyError(f"Version {target_version} not found for secret {path}")


def list_secrets(prefix=None):
    """List all secrets, optionally filtered by path prefix."""
    vault = _load()
    if prefix:
        return [s for path, s in vault.items() if path.startswith(prefix)]
    return list(vault.values())


def parse_uri(uri):
    """Parse a secret URI into its components.

    Format: secret://backend/path/to/secret#version (version optional)
    Returns: dict with backend, path, version
    """
    if not uri.startswith("secret://"):
        raise ValueError(f"Not a secret URI: {uri}")
    body = uri[len("secret://"):]
    version = None
    if "#" in body:
        body, version = body.split("#", 1)
    parts = body.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid URI format: {uri}")
    backend, path = parts
    return {"backend": backend, "path": path, "version": version}


def _audit_access(path, version):
    """Internal: log every secret access for audit trail."""
    audit_file = Path(__file__).parent / "vault_state" / "access_log.jsonl"
    with open(audit_file, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "event": "secret_accessed",
            "path": path,
            "version": version,
            "accessor": "resolver",  # in production: IAM principal
        }) + "\n")


def derive_secret_path(secret_type, finding_context):
    """
    Generate a stable, descriptive path for a secret based on context.

    Production strategy: organisation has a path naming convention,
    e.g.  /environment/team/service/secret-name

    Here we derive: /detected/<file_basename>/<secret_type>/<short_hash>
    """
    file_name = finding_context.get("file", "unknown").replace(".log", "")
    line = finding_context.get("line_number", 0)
    matched = finding_context.get("matched_text", "")
    short_hash = hashlib.sha256(f"{file_name}:{line}:{matched}".encode()).hexdigest()[:8]
    return f"detected/{file_name}/{secret_type}/{short_hash}"


def reset_vault():
    if VAULT_FILE.exists():
        VAULT_FILE.unlink()
    access_log = Path(__file__).parent / "vault_state" / "access_log.jsonl"
    if access_log.exists():
        access_log.unlink()
