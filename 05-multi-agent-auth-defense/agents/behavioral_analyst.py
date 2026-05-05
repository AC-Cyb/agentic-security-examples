"""
Behavioral Analyst Agent
========================
Specialised agent that analyses authentication context for behavioural anomalies
and signs of compromise.

Checks:
  - Impossible travel (geographic distance vs time)
  - User agent anomalies (bot signatures, automation tools)
  - Replay attack indicators
  - Privilege escalation in claims vs known user roles
  - IP reputation
  - Request pattern (sensitive endpoints, off-hours)

Outputs a structured finding the coordinator can use to make a decision.

In production: this would integrate with your behavioural analytics platform
(BioCatch, NuData, internal user behaviour scoring) and threat intelligence feeds.
Here we simulate the analysis using contextual rules.
"""

from datetime import datetime


class BehavioralAnalystAgent:
    """Specialised agent for behavioural and contextual analysis."""

    AGENT_NAME = "BehavioralAnalyst"

    # Track tokens we have seen before (replay detection)
    # In production this would be a Redis cache or distributed store
    _seen_jtis = set()
    _seen_jtis.add("tkn_replay")  # pre-seed for the demo scenario

    # Suspicious user agent patterns
    SUSPICIOUS_UA_PATTERNS = [
        ("curl/", "Command-line HTTP tool - unusual for end-user web auth"),
        ("python-requests/", "Python automation library"),
        ("PostmanRuntime/", "API testing tool"),
        ("Googlebot/", "Search engine crawler - not a legitimate user"),
        ("scrapy/", "Web scraping framework"),
        ("wget/", "Command-line download tool"),
    ]

    # Sensitive endpoints that warrant extra scrutiny
    SENSITIVE_ENDPOINTS = [
        "/admin/",
        "/payments/",
        "/transfer",
        "/policies",
        "/users",
    ]

    def analyze(self, request):
        """Analyze an auth request from a behavioural perspective."""
        context = request["context"]
        history = request.get("user_history")
        token = request["token"]
        claims = token.get("claims", {})

        findings = []
        risk_score = 0

        # === Check 1: IP reputation ===
        ip_rep = context.get("ip_reputation", "unknown")
        if ip_rep == "malicious":
            findings.append({
                "severity": "Critical",
                "issue": "malicious_source_ip",
                "detail": f"Source IP {context['source_ip']} ({context.get('ip_geo', 'unknown geo')}) is on threat intelligence lists.",
            })
            risk_score += 80
        elif ip_rep == "suspicious":
            findings.append({
                "severity": "High",
                "issue": "suspicious_source_ip",
                "detail": f"Source IP {context['source_ip']} has anomalous reputation indicators.",
            })
            risk_score += 50

        # === Check 2: Impossible travel ===
        if history and "last_login" in history:
            try:
                last_login = datetime.fromisoformat(history["last_login"])
                now = datetime.fromisoformat(context["timestamp"])
                minutes_since = (now - last_login).total_seconds() / 60

                last_geo = history.get("last_login_ip", "unknown")
                current_geo = context.get("ip_geo", "unknown")
                typical_locations = history.get("typical_locations", [])

                # Crude impossible travel detection
                if current_geo not in typical_locations and minutes_since < 60:
                    if any(country_token in current_geo for country_token in ["RU", "CN", "IR", "KP", "Tor"]):
                        findings.append({
                            "severity": "Critical",
                            "issue": "impossible_travel",
                            "detail": f"User typically logs in from {typical_locations}, but current request is from {current_geo} only {int(minutes_since)} minutes after last activity.",
                        })
                        risk_score += 80
                    else:
                        findings.append({
                            "severity": "High",
                            "issue": "anomalous_location",
                            "detail": f"Login from {current_geo}, which is unusual for this user (typical: {typical_locations}).",
                        })
                        risk_score += 50
            except (ValueError, KeyError):
                pass  # malformed timestamps, skip this check

        # === Check 3: User agent anomaly ===
        ua = context.get("user_agent", "")
        for pattern, description in self.SUSPICIOUS_UA_PATTERNS:
            if pattern in ua:
                # Different severity based on whether this is service/user
                if claims.get("sub", "").startswith("svc_"):
                    # Service accounts can legitimately use automation tools
                    pass
                else:
                    findings.append({
                        "severity": "High",
                        "issue": "suspicious_user_agent",
                        "detail": f"User account using suspicious user agent: {description}",
                    })
                    risk_score += 50
                break

        # Also check if user agent differs from typical
        if history:
            typical_uas = history.get("typical_user_agents", [])
            if typical_uas and ua and not any(tua in ua or ua in tua for tua in typical_uas):
                if not any(p[0] in ua for p in self.SUSPICIOUS_UA_PATTERNS):
                    # Already flagged above if suspicious, only flag here for "unusual but not malicious"
                    findings.append({
                        "severity": "Medium",
                        "issue": "unusual_user_agent",
                        "detail": f"User agent differs from this user's typical pattern.",
                    })
                    risk_score += 25

        # === Check 4: Replay detection ===
        jti = claims.get("jti")
        if jti:
            if jti in self._seen_jtis:
                findings.append({
                    "severity": "Critical",
                    "issue": "token_replay",
                    "detail": f"Token JTI '{jti}' has been seen before. Indicates token theft or replay attack.",
                })
                risk_score += 90
            else:
                self._seen_jtis.add(jti)

        # === Check 5: Privilege escalation ===
        if history and "expected_roles" in history:
            token_roles = set(claims.get("roles", []))
            expected_roles = set(history["expected_roles"])
            extra_roles = token_roles - expected_roles
            if extra_roles:
                findings.append({
                    "severity": "Critical",
                    "issue": "privilege_escalation",
                    "detail": f"Token claims roles {list(extra_roles)} that this user is not provisioned with. Possible token tampering or compromised IdP.",
                })
                risk_score += 100

        # === Check 6: Sensitive endpoint access ===
        path = context.get("request_path", "")
        is_sensitive = any(s in path for s in self.SENSITIVE_ENDPOINTS)
        if is_sensitive:
            # Sensitive endpoints add risk multiplicatively if other issues exist
            if risk_score > 0:
                risk_score = int(risk_score * 1.2)
                findings.append({
                    "severity": "Medium",
                    "issue": "sensitive_endpoint_with_anomalies",
                    "detail": f"Request targets sensitive endpoint ({path}) and other anomalies are present.",
                })

        # === Disposition recommendation ===
        if risk_score >= 80:
            recommended = "revoke"
        elif risk_score >= 50:
            recommended = "challenge"
        elif risk_score >= 25:
            recommended = "monitor"
        else:
            recommended = "allow"

        # Confidence varies based on data quality
        # If we have rich user history, confidence is higher
        # If we have no history, confidence is lower (cold start problem)
        if history:
            confidence = 0.85
        else:
            confidence = 0.60

        return {
            "agent": self.AGENT_NAME,
            "request_id": request["request_id"],
            "findings": findings,
            "risk_score": min(risk_score, 100),
            "recommended_disposition": recommended,
            "confidence": confidence,
            "reasoning": self._build_reasoning(findings, risk_score, history is not None),
        }

    def _build_reasoning(self, findings, risk_score, has_history):
        if not findings:
            base = f"No behavioural anomalies detected. Risk score: {risk_score}/100."
            if not has_history:
                base += " Note: no user history available - confidence reduced."
            return base

        critical = [f for f in findings if f["severity"] == "Critical"]
        if critical:
            return f"Critical behavioural indicators of compromise: {', '.join(f['issue'] for f in critical)}. Strong recommendation to deny access."

        high = [f for f in findings if f["severity"] == "High"]
        if high:
            return f"Significant behavioural anomalies: {', '.join(f['issue'] for f in high)}. Recommend additional verification."

        return f"Minor behavioural anomalies ({len(findings)} findings). Worth monitoring but not immediately blocking."
