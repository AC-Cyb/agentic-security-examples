# Remediation Agent

A tiered-autonomy authentication remediation agent. Takes detection findings as input,
evaluates them against a tiered policy, and either auto-remediates or requests human
approval depending on severity and impact — with a complete audit trail of every decision.

## Tiered Autonomy Model

| Severity | Approach |
|---|---|
| Critical | Auto-revoke sessions immediately. Request approval for password reset. Auto-notify SOC. |
| High | Request approval for session revocation. Auto-notify SOC. |
| Medium | Auto-notify SOC only. No automated user-disrupting actions. |
| Low | Auto-remediate hygiene issues (e.g. stale credential rotation). |

**Design principle: autonomy decreases as risk and impact increase.**
Reversible, low-impact actions auto-execute. Disruptive or irreversible actions require human approval.

## Architecture

```
Remediation Agent
├── Input:       Findings (from detection agent, SIEM, or threat intel)
├── Policy:      Tiered evaluation - severity + reversibility + impact
├── Execution:   Adapter layer - swappable for production identity providers
├── Oversight:   Human approval gate for high-impact actions
└── Audit:       Immutable JSONL log of every decision and rationale
```

## Setup

No dependencies beyond Python 3.8+. Just run:

```bash
cd 02-remediation-agent
python3 agent.py
```

The agent will process four sample findings interactively.
Type `y` to approve actions, anything else to reject.

## Files

- `agent.py` — main agent (decision engine + execution loop)
- `findings.py` — sample input findings (in production, comes from SIEM/detection)
- `environment.py` — simulated identity provider, sessions, SOC inbox
- `review.py` — inspect post-action environment state
- `state/` — simulated environment state (regenerated on reset)
- `audit/` — immutable audit log

## Modes

```bash
python3 agent.py             # Interactive mode (prompts for approvals)
python3 agent.py --dry-run   # Show what it would do without acting
python3 agent.py --reset     # Reset simulated environment
```

After running, inspect what changed:
```bash
python3 review.py
```

## Production Integration Points

In a real environment, replace the simulated functions in `environment.py`:

| Simulated Function | Production Equivalent |
|---|---|
| `revoke_session()` | Okta API, Azure AD revoke session, AWS IAM session deactivation |
| `force_password_reset()` | Identity provider password reset API |
| `notify_soc()` | Slack webhook, ServiceNow incident API, PagerDuty event API |
| `audit_log()` | Splunk HTTP Event Collector, Elasticsearch, immutable cloud storage |

The agent logic in `agent.py` stays identical. Only the adapters change.

## What Production Approval Workflows Look Like

The terminal prompt in this reference implementation is illustrative. In production:

- **Slack interactive messages** — agent posts to a channel with Approve/Reject buttons
- **Mobile push notifications** — for after-hours critical events
- **Approval queues** — ServiceNow or dedicated SOC tooling
- **Tiered approvers** — different severity levels routed to different humans

The pattern stays the same: agent proposes, human disposes, decision is logged.

## Regulatory Alignment

The patterns demonstrated here directly support:

- **DORA (EU)** — automated incident response with full audit trail and SOC notification within
  required timeframes. Tiered autonomy is explicitly compatible with DORA's emphasis on
  proportionate response.
- **NYDFS Part 500** — documented decisioning, human oversight on material actions, immutable
  audit trail aligned with the 72-hour notification requirement.
- **EU AI Act** — human-in-the-loop checkpoints designed by intent for high-risk autonomous
  decisions (Article 14 human oversight requirements).
- **GDPR Article 22** — meaningful human oversight on consequential automated decisions
  affecting users.

Every action logged with rationale provides the regulatory defensibility examiners are
increasingly looking for.
