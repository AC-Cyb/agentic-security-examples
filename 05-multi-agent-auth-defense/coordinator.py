"""
Coordinator Agent
=================
The orchestrator. Dispatches authentication requests to specialist agents,
synthesises their findings, and makes the final disposition decision.

Architecture decisions:
  - Specialists are queried in parallel (simulated here, parallel in production)
  - Each specialist contributes a risk score, findings, and confidence
  - Coordinator weighs findings by agent confidence and severity
  - Critical findings from any agent escalate disposition automatically
  - Coordinator's final decision includes a synthesis of all reasoning

This is the multi-agent coordination pattern - specialists feed a senior agent
that integrates their perspectives. Mirrors how mature SOC teams operate.
"""

import json
from datetime import datetime
from collections import Counter


class CoordinatorAgent:
    """Orchestrator that synthesises findings from specialist agents."""

    AGENT_NAME = "Coordinator"

    # Disposition severity ordering for combining
    DISPOSITION_RANK = {
        "allow": 0,
        "monitor": 1,
        "challenge": 2,
        "revoke": 3,
    }

    def __init__(self, specialists):
        """
        Args:
            specialists: list of specialist agent instances (TokenValidator, BehavioralAnalyst, etc.)
        """
        self.specialists = specialists

    def process(self, request):
        """
        Process an auth request through the full multi-agent pipeline.

        Returns the synthesised decision and full audit context.
        """
        # === Phase 1: Dispatch to specialists ===
        # In production these would run in parallel (asyncio, threading)
        # Here we run sequentially for clarity
        specialist_findings = []
        for agent in self.specialists:
            try:
                result = agent.analyze(request)
                specialist_findings.append(result)
            except Exception as e:
                specialist_findings.append({
                    "agent": agent.AGENT_NAME,
                    "request_id": request["request_id"],
                    "findings": [],
                    "risk_score": 0,
                    "recommended_disposition": "monitor",  # fail-safe
                    "confidence": 0.0,
                    "reasoning": f"Agent error: {e}",
                    "error": True,
                })

        # === Phase 2: Synthesise findings ===
        synthesis = self._synthesise(specialist_findings)

        # === Phase 3: Apply final decision policy ===
        decision = self._make_decision(synthesis, specialist_findings)

        # === Phase 4: Build the complete audit record ===
        return {
            "request_id": request["request_id"],
            "scenario_name": request.get("scenario_name", ""),
            "timestamp": datetime.now().isoformat(),
            "specialist_findings": specialist_findings,
            "synthesis": synthesis,
            "decision": decision,
        }

    def _synthesise(self, specialist_findings):
        """Combine findings from all specialists into a unified view."""
        all_findings = []
        for sf in specialist_findings:
            for finding in sf.get("findings", []):
                all_findings.append({
                    "from_agent": sf["agent"],
                    "agent_confidence": sf["confidence"],
                    **finding
                })

        # Aggregate severity counts
        severity_counts = Counter(f["severity"] for f in all_findings)

        # Compute weighted risk score
        # Each agent's risk score is weighted by its confidence
        weighted_risk = 0
        total_weight = 0
        for sf in specialist_findings:
            weight = sf.get("confidence", 0.5)
            weighted_risk += sf.get("risk_score", 0) * weight
            total_weight += weight

        unified_risk = (weighted_risk / total_weight) if total_weight > 0 else 0

        # Determine consensus disposition
        recommended = [sf.get("recommended_disposition", "monitor") for sf in specialist_findings]

        return {
            "all_findings": all_findings,
            "severity_counts": dict(severity_counts),
            "weighted_risk_score": round(unified_risk, 1),
            "specialist_recommendations": recommended,
            "max_severity": self._max_severity(all_findings),
        }

    def _max_severity(self, findings):
        order = ["Critical", "High", "Medium", "Low"]
        for sev in order:
            if any(f["severity"] == sev for f in findings):
                return sev
        return "None"

    def _make_decision(self, synthesis, specialist_findings):
        """
        Apply the coordinator's decision policy.

        Policy hierarchy:
          1. ANY critical finding from a high-confidence agent -> revoke
          2. Multiple high findings or single critical from medium-confidence -> revoke
          3. Single high finding -> challenge
          4. Medium findings -> monitor (allow but log)
          5. No issues -> allow
        """
        all_findings = synthesis["all_findings"]
        max_sev = synthesis["max_severity"]
        risk = synthesis["weighted_risk_score"]

        # Check for high-confidence critical findings
        critical_findings = [f for f in all_findings if f["severity"] == "Critical"]
        high_conf_critical = [f for f in critical_findings if f["agent_confidence"] >= 0.8]

        if high_conf_critical:
            disposition = "revoke"
            requires_human = False  # high confidence critical = auto-revoke
            rationale = f"Auto-revoke: {len(high_conf_critical)} critical finding(s) from high-confidence agent(s). Issues: {', '.join(f['issue'] for f in high_conf_critical)}."

        elif critical_findings:
            disposition = "revoke"
            requires_human = True  # lower confidence = human review
            rationale = f"Revoke recommended: critical findings present but with lower confidence. Human review advised. Issues: {', '.join(f['issue'] for f in critical_findings)}."

        elif risk >= 60:
            disposition = "challenge"
            requires_human = False
            rationale = f"Challenge: weighted risk score {risk}/100 indicates elevated risk. Step-up authentication required."

        elif max_sev == "High":
            disposition = "challenge"
            requires_human = False
            rationale = f"Challenge: high-severity findings present but no critical compromise indicators. Step-up authentication required."

        elif max_sev == "Medium" or risk >= 25:
            disposition = "monitor"
            requires_human = False
            rationale = f"Allow with monitoring: {len(all_findings)} minor finding(s). Request is permitted but logged for review."

        else:
            disposition = "allow"
            requires_human = False
            rationale = "Allow: no significant findings from any specialist agent."

        # Audit context for the decision
        return {
            "disposition": disposition,
            "requires_human_review": requires_human,
            "rationale": rationale,
            "weighted_risk_score": risk,
            "max_severity": max_sev,
            "finding_count": len(all_findings),
            "decision_method": "multi_agent_synthesis",
        }
