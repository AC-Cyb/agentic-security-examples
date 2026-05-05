# Secrets & PII Agent v2 — With Vault Integration

The full discovery and vaulting pipeline. When the agent finds a secret in a log file,
it does four things: stores the value in AWS Secrets Manager, registers it in a
discoverable index, replaces the file content with a reference URI, and notifies SOC.

The application stays functional. The SOC team has visibility. The audit trail is complete.

This is the architecture pattern that turns secret detection from a post-hoc cleanup
exercise into a continuous discovery and lifecycle management system.

## What's New vs v1

| Capability | v1 | v2 |
|---|---|---|
| Detect secrets in logs | ✓ | ✓ |
| AI false positive filtering | ✓ | ✓ |
| File redaction | `[REDACTED-AWS_KEY]` | `{{secret://aws-secretsmanager/.../#v1}}` |
| Original secret value | Lost | Stored in vault |
| App can recover value | No | Yes via resolver |
| SOC discovery view | No | Full registry view with filters |
| Owner team attribution | No | Yes |
| Rotation lifecycle tracking | No | Yes |
| Audit trail with raw secrets | Yes (problem) | Hashed only |

## The Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                        DETECTION PIPELINE                          │
│                                                                    │
│   Logs ─→ Regex Patterns ─→ AI Validation ─→ True Positives        │
└────────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┴───────────────┐
                │                               │
                ▼                               ▼
       ┌─────────────────┐           ┌──────────────────┐
       │ Secrets/Custom  │           │       PII        │
       │  → VAULT path   │           │  → REDACT path   │
       └─────────────────┘           └──────────────────┘
                │                               │
                ▼                               │
   ┌────────────────────────┐                   │
   │  AWS Secrets Manager   │                   │
   │  (vault.put_secret)    │                   │
   └────────────────────────┘                   │
                │                               │
                ▼                               │
   ┌────────────────────────┐                   │
   │   Secret Registry      │                   │
   │  (registry.register)   │                   │
   └────────────────────────┘                   │
                │                               │
                └───────────────┬───────────────┘
                                ▼
              ┌─────────────────────────────────┐
              │   File Replacement              │
              │  Secrets → {{secret://...#v1}}  │
              │  PII     → [REDACTED-TYPE]      │
              └─────────────────────────────────┘
                                │
                                ▼
              ┌─────────────────────────────────┐
              │  Three audit trails:            │
              │   - Audit log (hashed)          │
              │   - SOC inbox (notifications)   │
              │   - Vault access log            │
              └─────────────────────────────────┘
```

## How It Works

### 1. Detection
Same as v1 — regex finds candidates, AI filters false positives.

### 2. Vaulting (new)
For each validated secret in the Secrets or Custom category:
- Generate a stable secret path: `detected/<file>/<type>/<hash>`
- Store value in AWS Secrets Manager (simulated)
- Get back a URI: `secret://aws-secretsmanager/detected/debug/aws_access_key/2d279d1f`
- Get back a version: `v1`

### 3. Registration (new)
Every vaulted secret gets a registry entry with:
- Stable secret_id (hash of context)
- Vault URI and current version
- Severity, category, regulatory tags
- Owner team (derived from file context)
- Rotation status and target date
- Discovery metadata

### 4. Replacement (changed)
- Secrets are replaced with references: `{{secret://aws-secretsmanager/.../#v1}}`
- PII is replaced with redactions: `[REDACTED-EMAIL]`, `****-****-****-9903`

The redacted file is now both safe to share AND functional — apps can resolve references.

### 5. Notification & Audit (improved)
- SOC inbox gets a notification with severity and lookup hint
- Audit log records hashed values only — never raw secrets
- Vault has its own access log for every secret retrieval

## Quick Start

```bash
cd 04-secrets-agent-v2

# One-time: generate sample logs with embedded secrets
python3 generate_logs.py

# Reset everything (vault, registry, audit)
python3 agent.py --reset

# Run the full pipeline
python3 agent.py --auto-approve

# View the SOC operational dashboard
python3 soc_view.py

# Filter by severity
python3 soc_view.py --severity Critical

# Filter by owning team
python3 soc_view.py --owner billing

# See how an app would resolve references
python3 resolver.py

# Compare original vs redacted
diff logs/debug.log redacted/debug.log
```

## Files

| File | Purpose |
|---|---|
| `agent.py` | Main agent — detection, validation, vaulting, replacement |
| `vault.py` | Vault interface (simulates AWS Secrets Manager) |
| `registry.py` | Discovery index — the SOC's lookup table |
| `resolver.py` | Sample app library for fetching secrets at runtime |
| `soc_view.py` | SOC operational dashboard |
| `patterns.py` | Detection patterns library |
| `generate_logs.py` | Sample log generator |

## Production Path

| Reference Implementation | Production |
|---|---|
| `vault.put_secret()` | `boto3.client('secretsmanager').create_secret()` |
| `vault.get_secret()` | `boto3.client('secretsmanager').get_secret_value()` |
| File-based registry | DynamoDB / Postgres with API |
| `derive_owner_team()` heuristic | CODEOWNERS / ServiceNow CMDB lookup |
| Local audit JSONL | Splunk HEC / Elasticsearch / immutable bucket |
| `resolver.py` | Production library shipped to app teams (with caching, IAM) |
| Static rotation_status | Live integration with rotation scheduler |
| Terminal SOC view | Web dashboard for SOC team |

The agent core stays identical. Only the adapters change.

## Why This Pattern Matters

### For Applications
Config files contain `{{secret://...}}` references rather than actual secrets. The
references are safe to commit to git, paste in tickets, send in emails. The actual
values are fetched at runtime via the resolver, with full IAM-controlled access.

### For SOC Teams
Every secret in the organisation is in the registry. Filter by severity, owner,
rotation status. Track sightings to find re-exposure. Coordinate rotation campaigns.
This is the **operational tooling** that turns secret management from a "we have
a vault" claim into a "here's our actual posture" reality.

### For Compliance
- **DORA** — automated detection and response with full audit trail
- **PCI-DSS Req 3.5** — cryptographic key management with documented lifecycle
- **GDPR Article 30** — record of processing activities with attribution
- **SOC 2** — change control, access logging, secrets management
- **NYDFS Part 500** — cybersecurity event tracking and notification

### For Engineering Velocity
Developers can ship without touching real credentials. The reference URI in their
config is the only thing they see. The vault and resolver handle everything else.
Security becomes infrastructure rather than friction.

## What This Demonstrates

For panel discussions and interviews, this agent demonstrates:

- **The reference-not-redaction pattern** — secrets become discoverable, applications stay functional
- **Hybrid intelligence** — deterministic rules + AI reasoning at appropriate layers
- **Lifecycle management** — discovery, vaulting, registration, rotation, audit
- **Autonomous execution with safety nets** — all severities auto-vault and replace; reversibility comes from vault versioning, original file preservation, and SOC notification
- **Defensive-by-default audit** — hash values in logs, separate vault access tracking
- **Swappable architecture** — vault, registry, and resolver are clean adapter layers

This is what good agentic security architecture looks like in code.
