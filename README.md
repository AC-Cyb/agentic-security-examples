# Agentic Security Examples

Working reference implementations of the agentic Defense model — autonomous security agents
that detect, decide, act, and log, with human oversight designed in by intent rather than added as friction.

These are minimal, runnable examples built to illustrate the core architectural patterns that make
agentic security work in regulated environments. They are intentionally simple — the value is in the
design, not the line count.

## Why These Exist

Modern enterprise security has a structural problem: human-speed response cannot keep pace with
machine-speed threats. The answer is autonomous Defense — but autonomy without governance is
just a faster way to get into trouble.

These examples demonstrate the design principles that make autonomy safe:

- **Tiered autonomy** — speed where reversible and low-risk, oversight where impact is high
- **Bounded action spaces** — agents can only do what they are explicitly designed to do
- **Human in the loop by intent** — checkpoints placed where judgment matters, not as friction
- **Immutable audit trail** — every decision logged with rationale for regulatory defensibility
- **Separation of concerns** — policy, execution, and environment are cleanly decoupled

## Projects

### [01 — Detection Agent](./01-detection-agent/)

Reads security log files, identifies anomalous patterns across eight detection categories,
scores findings by severity, and generates an HTML risk report with actionable recommendations.

**Demonstrates:** signal aggregation, pattern detection, severity tiering, regulatory-aware reporting.

### [02 — Remediation Agent](./02-remediation-agent/)

Takes detection findings and responds with tiered autonomy — auto-revoking suspicious sessions,
requesting approval for user-disrupting actions, and notifying the SOC, all with a complete audit trail.

**Demonstrates:** policy-based decisioning, tiered autonomy, human-in-the-loop design, audit trail discipline.

### [03 — Secrets & PII Detection Agent](./03-secrets-pii-agent/)

Hybrid intelligence agent that scans logs for exposed credentials, secrets, and PII —
combining fast deterministic regex with AI reasoning to filter false positives, then taking
tiered remediation actions (auto-redact + notify SOC) with full audit trail.

**Demonstrates:** hybrid intelligence pattern (rules + AI), false positive reduction, automated
remediation with regulatory mapping, the architecture pattern that distinguishes scripts from agents.

### [04 — Secrets Agent v2 with Vault Integration](./04-secrets-agent-v2/)

Extends Project 3 with the full discovery and vaulting pipeline. When the agent finds a secret,
it stores the value in AWS Secrets Manager (simulated), registers it in a discoverable index,
replaces the file content with a reference URI like `{{secret://...#v1}}`, and notifies SOC.
Includes a runtime resolver showing how apps fetch values at runtime, and a SOC operational
dashboard for the security team.

**Demonstrates:** the reference-not-redaction pattern, swappable vault adapter architecture,
discoverable secrets registry, runtime resolution, defensive-by-default audit (hashed values).

### [05 — Multi-Agent Authentication Defense](./05-multi-agent-auth-defense/)

Multi-agent coordination applied to authentication validation. A coordinator agent dispatches
auth requests to specialist agents — a Token Validator and a Behavioral Analyst — synthesises
their findings, and produces a unified decision (allow, monitor, challenge, revoke). Designed
for clean extension with additional specialists.

**Demonstrates:** multi-agent orchestration, specialist-coordinator pattern, weighted synthesis
of agent findings, tiered autonomy with human-in-the-loop on ambiguous critical findings.

## Quick Start

```bash
# Detection agent
cd 01-detection-agent
python3 analyser.py
open reports/risk_report.html

# Remediation agent
cd 02-remediation-agent
python3 agent.py
python3 review.py

# Secrets & PII agent
cd 03-secrets-pii-agent
python3 generate_logs.py    # one-time, creates sample logs
python3 agent.py
open reports/findings_report.html

# Secrets agent v2 — with vault integration
cd 04-secrets-agent-v2
python3 generate_logs.py
python3 agent.py            # detect, vault, register, replace
python3 soc_view.py         # SOC operational view
python3 resolver.py         # see how apps resolve references

# Multi-agent auth Defense
cd 05-multi-agent-auth-defense
python3 run.py              # process all sample auth requests
python3 run.py --request REQ-003  # examine one specific scenario
```

Each project has its own README with detailed setup and usage.

## Architectural Principles

These examples embody five principles that translate directly to production agentic security:

1. **Detect → Decide → Act → Log** is the canonical loop. Every agent in this repository follows it.

2. **Autonomy is earned by reversibility.** An agent should auto-execute only actions that are
   reversible and low-impact. Anything that disrupts users, changes data, or has regulatory implications
   should require human approval by default.

3. **Policy is separate from execution.** The decision logic of what to do should live independently
   from how to do it. This makes the agent testable, auditable, and adaptable.

4. **The environment is a swappable adapter.** In these examples, the environment is simulated.
   In production, the same agent logic plugs into Okta, Azure AD, Slack, ServiceNow, or whatever
   real systems the organisation uses. The agent does not care.

5. **Audit logs are not optional.** Every decision — including the decision *not* to act — must be
   logged with timestamp, rationale, and outcome. This is what makes agentic systems defensible
   under regulatory scrutiny.

## Regulatory Alignment

The patterns demonstrated here directly support:

- **DORA (EU)** — automated incident response with full audit trail and SOC notification within
  required timeframes
- **NYDFS Part 500** — documented decisioning, human oversight on material actions, continuous monitoring
- **EU AI Act** — human-in-the-loop checkpoints designed by intent for high-risk autonomous decisions
- **SR 11-7 (US Federal Reserve / OCC)** — model risk management principles when extended to ML-based
  detection layers
- **GDPR Article 22** — meaningful human oversight on consequential automated decisions

## Production Path

These examples are reference implementations, not production code. The path to production looks like:

| Layer | Reference | Production |
|---|---|---|
| Detection input | Synthetic log files | SIEM (Splunk, Elastic, Sentinel) |
| Decision policy | Hardcoded rules | Configurable policy engine, versioned in Git |
| Identity actions | Simulated | Okta API, Azure AD Graph, AWS IAM |
| SOC notifications | Local JSON file | Slack, ServiceNow, PagerDuty |
| Audit log | Local JSONL file | Immutable cloud storage, SIEM pipeline |
| Approval workflow | Terminal prompt | Slack interactive, approval queue, mobile app |

The agent logic stays the same. Only the adapters change.

## Extending These Agents

Concrete next steps for taking these further:

- **AI reasoning layer** — call an LLM to enrich findings with context-aware analysis and natural-language briefs
- **Threat intelligence enrichment** — VirusTotal, AbuseIPDB lookups for source IPs at decision time
- **Multi-agent coordination** — separate threat intel, vulnerability assessment, and response agents working in concert
- **Learning loop** — when humans reject agent recommendations, feed back into policy tuning
- **Tool calling** — let the AI decide which actions to take rather than following fixed policy

## License

MIT — use freely, attribution appreciated, no warranty. See [LICENSE](./LICENSE).

## About

Built as reference implementations of the agentic security architecture — the foundation for how
autonomous Defense systems work in regulated enterprise environments.
