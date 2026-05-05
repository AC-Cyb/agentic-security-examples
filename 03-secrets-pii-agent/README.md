# Secrets & PII Detection Agent

A hybrid intelligence agent that scans log files for exposed secrets, credentials, and PII —
combining fast deterministic regex with AI reasoning to filter false positives, then taking
tiered remediation actions with full audit trail.

## What It Does

**Detects 19+ pattern types across 3 categories:**

**Secrets (Critical/High):**
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Slack API Tokens
- JSON Web Tokens (JWT)
- Stripe API Keys (test and live)
- Private cryptographic keys
- Generic API keys
- Passwords in plaintext or URLs

**PII (Critical/High/Medium/Low):**
- Credit card numbers (with Luhn validation)
- US Social Security Numbers
- Email addresses
- US phone numbers
- IP addresses (with internal/external classification)
- IBAN bank account numbers
- Passport numbers (context-tagged)

**Custom (configurable):**
- Internal employee IDs
- Customer account identifiers
- Add your own in `patterns.py`

## The Hybrid Intelligence Pattern

This agent demonstrates the architectural pattern that separates **scripts** from **agents**:

```
Layer 1: REGEX        - Fast, deterministic, finds candidates  (high recall)
Layer 2: AI REASONING - Validates context, filters false positives (high precision)
Layer 3: ACTION       - Tiered remediation with human oversight
Layer 4: AUDIT        - Immutable log of every decision
```

### Why this matters

Pure regex finds everything — including hundreds of false positives that drown signal in noise.
Pure AI is slow and expensive at log scale.

The hybrid approach uses regex to find candidates fast, then lets AI reason about which are real.
**Result: high recall, high precision, manageable cost.**

The AI layer in this reference implementation is simulated with deterministic context-aware rules
so the demo runs without external dependencies. In production, replace `ai_validate_finding()`
in `agent.py` with a real Claude API call. The interface stays identical.

## Tiered Remediation

| Severity | Action |
|---|---|
| All severities | Notify SOC + auto-redact |
| All findings | Logged to immutable audit trail |

**Why auto-redact at all severities:** redaction is non-destructive — original files
remain on disk untouched, only a redacted copy is created in `redacted/`. SOC is
notified for every finding, so awareness is maintained. The cost of a missed
high-severity finding is far higher than the cost of an unnecessary redaction.

## Setup

No external dependencies. Just Python 3.8+.

```bash
cd secrets_agent
python3 generate_logs.py    # Create sample logs (one-time)
python3 agent.py            # Run the agent
open reports/findings_report.html
```

## Modes

```bash
python3 agent.py                    # Full hybrid run with AI validation
python3 agent.py --no-ai            # Pure regex only (more false positives)
python3 agent.py --dry-run          # Show what it would do, no actions
python3 agent.py --auto-approve     # No prompts (testing only)
python3 agent.py --reset            # Clear all output and start fresh
```

## Files

- `agent.py` — main agent: detection, AI reasoning, tiered action, reporting
- `patterns.py` — all detection patterns with severity, regulatory mapping, AI hints
- `generate_logs.py` — generates sample logs containing realistic secrets/PII
- `logs/` — input log files
- `redacted/` — output: redacted copies of input files (regenerated each run)
- `reports/findings_report.html` — human-readable findings report
- `audit/audit.jsonl` — immutable audit trail of every decision
- `audit/soc_inbox.json` — SOC notification queue

## Architecture Decisions

### Why regex first, AI second
At log scale, you process millions of lines. Regex is microseconds, AI calls are hundreds of
milliseconds. Hybrid means AI only sees candidates that already matched a pattern — typically
under 1% of total volume.

### Why auto-redact at all severities
The redacted file is a separate copy — originals remain untouched on disk. Combined
with SOC notification on every finding, the cost asymmetry favours redacting rather
than waiting. In production, the equivalent would be: redact the log copy that goes
to your SIEM, leave the source file alone, and let SOC drive the actual remediation
on the source system.

### Why immutable audit log
Under DORA, NYDFS Part 500, GDPR Article 30, and SOC 2, you need to demonstrate not just that
controls existed but that decisions were made deliberately and are reviewable after the fact.
JSONL append-only logs are the simplest defensible format.

## Production Path

| Reference Implementation | Production |
|---|---|
| Local file system scan | Streaming pipeline (Splunk HEC, Kafka, Kinesis) |
| Simulated AI reasoning | Claude API or local LLM call |
| Local SOC inbox JSON | Slack webhook, ServiceNow incident, PagerDuty event |
| Local audit JSONL | Splunk, Elasticsearch, immutable cloud storage |
| Static patterns | Versioned policy repo, hot-reloadable patterns |
| Manual approval prompt | Slack interactive buttons, mobile push |

The agent core stays the same. Only the adapters change.

## Regulatory Alignment

This agent directly supports compliance with:

- **PCI-DSS** — credit card and key detection, automated remediation
- **GDPR** — PII discovery, redaction, breach prevention, audit trail (Article 30)
- **NYDFS Part 500** — covered information protection, documented controls
- **SR 11-7** — when extended with ML detection, model governance applies
- **DORA** — operational resilience through automated detection and response
- **SOC 2** — secrets management, change control, audit evidence

## Extending the Agent

**Add a new pattern:** edit `patterns.py`, add to the appropriate list with severity,
regulatory tags, and an `validation_hint` that helps the AI reason about it.

**Replace simulated AI with real Claude API:**

```python
import anthropic

def ai_validate_finding(finding):
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=200,
        messages=[{
            "role": "user",
            "content": f"""You are a security analyst validating a regex-detected finding.

Pattern: {finding['pattern_name']}
Description: {finding['description']}
Validation hint: {finding['validation_hint']}
Matched text: {finding['matched_text']}
Surrounding line: {finding['line_content']}

Is this a true positive (real credential/PII) or false positive (placeholder/test value)?
Respond as JSON: {{"validated": bool, "confidence": float 0-1, "reasoning": "brief explanation"}}"""
        }]
    )
    return json.loads(response.content[0].text)
```

**Add streaming input:** replace the file scan in `scan_file()` with a generator that
reads from a Kafka topic, syslog stream, or cloud log subscription. The detection logic
operates on lines so it works the same.

## What This Demonstrates

For panel discussions and interviews, this agent demonstrates:

- **Hybrid intelligence** — combining deterministic and AI-driven approaches at appropriate layers
- **Tiered autonomy** — speed where safe, oversight where it matters
- **Defensive architecture** — false positives are filtered before action, not after
- **Regulatory readiness** — every finding mapped to relevant frameworks
- **Production thinking** — clean separation between policy, detection, and action

This is what agentic security looks like in practice. Not magic. Architecture.
