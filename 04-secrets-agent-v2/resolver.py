"""
Secret Resolver
===============
Sample code showing how an application would resolve a secret reference back
to its actual value at runtime.

This is the library you'd ship to your application teams. They include it,
their config files contain {{secret://...}} references, and the resolver
fetches values from the vault at runtime.

Usage in an application:

    from resolver import resolve_secrets_in_string, resolve_config

    # Resolve a single reference
    db_password = resolve_secret("secret://aws-secretsmanager/prod/db/password")

    # Resolve all references in a config string
    cleaned_config = resolve_secrets_in_string(config_template)

    # Resolve all references in a config dict
    cleaned_config = resolve_config(config_dict)

In production:
  - Caching layer to avoid hammering the vault on every resolution
  - IAM role/principal context for authorisation
  - Circuit breaker for vault outages
  - Metrics on resolution latency and failures
"""

import re
import json
from pathlib import Path
import vault

# Pattern to find {{secret://...}} references in any text
REFERENCE_PATTERN = re.compile(r"\{\{(secret://[^\}]+)\}\}")


def resolve_secret(uri):
    """
    Resolve a single secret URI to its actual value.

    Args:
        uri: e.g. "secret://aws-secretsmanager/prod/db/password#v2"

    Returns:
        The actual secret value as a string.

    Raises:
        KeyError if the secret doesn't exist
        ValueError if the URI is malformed
    """
    parsed = vault.parse_uri(uri)
    return vault.get_secret(parsed["path"], parsed["version"])


def resolve_secrets_in_string(text):
    """
    Resolve all {{secret://...}} references in a string.

    Useful for:
      - Application config files with embedded references
      - Log line replacement for offline analysis
      - Template processing
    """
    def _replace(match):
        try:
            return resolve_secret(match.group(1))
        except (KeyError, ValueError) as e:
            return f"[RESOLVE_ERROR:{e}]"

    return REFERENCE_PATTERN.sub(_replace, text)


def resolve_config(obj):
    """
    Recursively resolve all secret references in a config object.

    Walks dicts, lists, strings - resolves any string containing {{secret://...}}
    """
    if isinstance(obj, str):
        return resolve_secrets_in_string(obj)
    if isinstance(obj, dict):
        return {k: resolve_config(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve_config(item) for item in obj]
    return obj


# ===== DEMO =====

def demo():
    """Demonstrate the resolver with a sample config that has secret references."""
    print("=" * 60)
    print("RESOLVER DEMO - How an Application Uses Secret References")
    print("=" * 60)

    # This is what an app config file would look like AFTER the agent has run
    app_config_template = {
        "service_name": "billing-api",
        "database": {
            "url": "postgresql://app_user:{{secret://aws-secretsmanager/detected/debug/password_assignment/abc12345}}@db.internal:5432/app_prod",
            "max_connections": 20,
        },
        "stripe": {
            "api_key": "{{secret://aws-secretsmanager/detected/debug/stripe_key/xyz98765}}",
            "webhook_secret": "static_value_not_a_secret",
        },
        "github": {
            "sync_token": "{{secret://aws-secretsmanager/detected/debug/github_token/def54321}}",
        },
    }

    print("\n1. Application config template (with secret references):")
    print(json.dumps(app_config_template, indent=2))

    print("\n2. After resolver processes it (fetches from vault):")
    try:
        resolved = resolve_config(app_config_template)
        # Mask actual values for safe display
        masked = json.loads(json.dumps(resolved))  # deep copy
        if isinstance(masked.get("database", {}).get("url"), str):
            masked["database"]["url"] = re.sub(r":[^@]+@", ":***MASKED***@", masked["database"]["url"])
        if "stripe" in masked:
            masked["stripe"]["api_key"] = "***MASKED***"
        if "github" in masked:
            masked["github"]["sync_token"] = "***MASKED***"
        print(json.dumps(masked, indent=2))

        print("\n3. The application can now connect to its dependencies.")
        print("   Real values were fetched from the vault at runtime.")
        print("   None of the actual secrets touched the config file or git history.")
    except Exception as e:
        print(f"\nResolver error: {e}")
        print("(Run agent.py first to populate the vault with discovered secrets.)")


if __name__ == "__main__":
    demo()
