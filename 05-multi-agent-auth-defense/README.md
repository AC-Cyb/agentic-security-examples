# Multi-Agent Authentication Defence

A working reference implementation of multi-agent coordination applied to
authentication validation for web applications and APIs.

When an authentication request arrives, multiple specialised agents analyse it
from different angles in parallel. A coordinator agent synthesises their findings
and makes the final disposition decision — allow, monitor, challenge, or revoke.

This is the architectural pattern that mature SOC teams already follow with humans.
This implementation shows what it looks like when those specialists are agents.

## Why Multi-Agent

Authentication is a multi-dimensional problem. A token can be:

- Cryptographically valid but used from a malicious context
- Behaviourally normal but structurally compromised
- Coming from a known-good IP but with privilege escalation in claims
- Apparently legitimate but actually replayed

A single monolithic agent trying to evaluate all dimensions at once produces
muddled reasoning. Specialists with focused expertise produce clearer findings.
A coordinator that synthesises specialist input produces better decisions than
either agent alone could.

This is the pattern modern security operations are heading toward. This codebase
is a working demonstration of how to architect it.

## Architecture

```
Authentication Request
         │
         ▼
┌────────────────────┐
│  Coordinator Agent │
│  - Dispatches to specialists
│  - Synthesises findings
│  - Applies decision policy
└────────────────────┘
   │       │       │
   ▼       ▼       ▼
┌────────┐ ┌────────┐ ┌────────┐
│ Token  │ │ Behav. │ │ Threat │
│ Valid. │ │ Anal.  │ │ Intel  │
└────────┘ └────────┘ └────────┘
   │       │       │
   └───────┴───────┘
           │
           ▼
   ┌──────────────┐
   │   Decision   │
   │ allow/monitor/
   │ challenge/   │
   │   revoke     │
   └──────────────┘
           │
           ▼
   ┌──────────────┐
   │ Audit Trail  │
   └──────────────┘
```

Each specialist agent is independent. The coordinator orchestrates them, weighs
their inputs by confidence, and produces the final decision. Adding a new
specialist (like a Threat Intel agent) is a clean extension — the coordinator
doesn't need to change.

## What's Included In This Implementation

**Coordinator Agent.** Dispatches to specialists, synthesises findings into a
weighted risk score, applies decision policy. Tiered autonomy built in — high-
confidence critical findings auto-revoke, lower-confidence findings flag for
human review.

**Token Validator Agent.** Analyses authentication tokens for structural and
cryptographic validity. Detects:
- Algorithm confusion attacks (alg=none, weak algorithms)
- Untrusted issuers, audience mismatches
- Expired or excessively long-lived tokens
- Missing required claims

**Behavioral Analyst Agent.** Analyses request context for behavioural anomalies
and signs of compromise. Detects:
- Impossible travel scenarios
- Suspicious user agents (automation tools, bot signatures)
- Token replay attacks (JTI tracking)
- Privilege escalation in claims
- Sensitive endpoint targeting

**Eight Sample Scenarios.** Pre-built request scenarios covering valid traffic,
expired tokens, algorithm confusion attacks, impossible travel, replay attacks,
privilege escalation, service account legitimate use, and anomalous user agents.

**Immutable Audit Log.** Every decision logged with full context — specialist
findings, coordinator synthesis, final decision, and rationale. JSONL format
suitable for SIEM ingestion.

## Easy To Extend

The system is designed to add more specialist agents. Two examples:

**Threat Intel Agent** (next to add). Cross-references the request against
known compromised tokens, IOCs, threat feeds. Adds a third perspective the
coordinator can integrate.

**Geo-Risk Agent.** Specialises in geographic and network-level risk —
ASN reputation, country-level risk scores, hosting provider classification.

Adding either is an exercise in implementing the same `analyze(request)`
interface and registering with the coordinator. No coordinator changes
needed.

## Running It

```bash
# Process all sample scenarios
python3 run.py

# Process one specific scenario
python3 run.py --request REQ-003

# JSON output for piping to other tools
python3 run.py --json

# Reset audit log
python3 run.py --reset
```

## Files

- `run.py` — main runner
- `coordinator.py` — coordinator agent
- `agents/token_validator.py` — token validation specialist
- `agents/behavioral_analyst.py` — behavioural analysis specialist
- `tokens.py` — sample request scenarios
- `audit/` — immutable decision log

## Production Path

This is a reference implementation. Production hardening looks like:

| Reference | Production |
|---|---|
| Sequential dispatch | Parallel dispatch (asyncio, threading) |
| In-process specialists | Microservice agents communicating via gRPC or message queue |
| Static rules in agents | Configurable policy engines, hot-reloadable |
| Simulated reasoning | Real Claude API calls for context-sensitive decisions |
| Local audit JSONL | SIEM forwarding (Splunk HEC, Elastic, Datadog) |
| Static threat intel | Live feeds (MISP, AbuseIPDB, ThreatConnect) |
| In-memory JTI cache | Distributed cache (Redis cluster) |
| Hardcoded user history | User behaviour analytics platform integration |

The coordinator pattern stays unchanged. Only the adapters change.

## Why This Pattern Matters For Agentic Security

This codebase is a working answer to a question that comes up repeatedly in
agentic security conversations: *"What does multi-agent coordination actually
look like in practice?"*

The honest answer is that it looks like specialists with bounded scope feeding
a synthesiser that integrates their perspectives. Not one giant agent trying to
do everything. Not a swarm of agents acting independently. A clean hierarchy
where each layer adds value the layer above could not produce alone.

That pattern is going to be the dominant architecture for security automation
over the next several years. The systems being built today that do not follow
it will not scale. The systems that do follow it will be the ones that hold up
under regulatory and operational scrutiny.

## Regulatory Alignment

The patterns demonstrated here directly support:

- **EU AI Act** — human oversight on disruptive decisions, full reasoning audit
- **DORA** — operational resilience, audit trail, defined response paths
- **NYDFS Part 500** — documented decisioning, continuous monitoring of authentication events
- **GDPR Article 22** — meaningful human oversight on consequential automated decisions
- **SR 11-7** — model risk management when AI reasoning is integrated into specialist agents
