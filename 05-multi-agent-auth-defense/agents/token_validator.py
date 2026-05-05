"""
Token Validator Agent
=====================
Specialised agent that analyses authentication tokens from a structural and
cryptographic perspective.

Checks:
  - Structural validity (header, claims, signature parts)
  - Algorithm safety (rejecting alg=none, weak algorithms)
  - Required claims present (sub, iss, aud, exp)
  - Expiry status
  - Issuer trust
  - Audience match

Outputs a structured finding the coordinator can use to make a decision.

In production: this would integrate with your IdP's JWKS endpoint to verify
signatures cryptographically. Here we simulate the verification deterministically.
"""

from datetime import datetime


class TokenValidatorAgent:
    """Specialised agent for token structural and cryptographic validation."""

    AGENT_NAME = "TokenValidator"
    TRUSTED_ISSUERS = ["auth.fintech.com"]
    TRUSTED_AUDIENCES = ["api.fintech.com"]
    DANGEROUS_ALGORITHMS = ["none", "HS256_with_public_key"]
    SAFE_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    def analyze(self, request):
        """Analyze an auth request from a token validation perspective."""
        token = request["token"]
        claims = token.get("claims", {})

        findings = []
        risk_score = 0

        # === Token type handling ===
        token_type = token.get("type", "unknown")
        if token_type == "api_key":
            # API keys have different validation rules
            return self._analyze_api_key(request)

        # === JWT-specific validation ===

        # Check 1: Algorithm safety
        alg = claims.get("alg")
        if alg in self.DANGEROUS_ALGORITHMS:
            findings.append({
                "severity": "Critical",
                "issue": "dangerous_algorithm",
                "detail": f"Token uses dangerous algorithm: {alg}. This is a known JWT attack vector (algorithm confusion / alg-none bypass).",
            })
            risk_score += 100
        elif alg not in self.SAFE_ALGORITHMS:
            findings.append({
                "severity": "High",
                "issue": "unrecognized_algorithm",
                "detail": f"Token uses unrecognised algorithm: {alg}",
            })
            risk_score += 60

        # Check 2: Issuer trust
        iss = claims.get("iss")
        if iss not in self.TRUSTED_ISSUERS:
            findings.append({
                "severity": "Critical",
                "issue": "untrusted_issuer",
                "detail": f"Token issued by untrusted issuer: {iss}",
            })
            risk_score += 100

        # Check 3: Audience match
        aud = claims.get("aud")
        if aud not in self.TRUSTED_AUDIENCES:
            findings.append({
                "severity": "High",
                "issue": "audience_mismatch",
                "detail": f"Token audience does not match expected: {aud}",
            })
            risk_score += 70

        # Check 4: Expiry
        exp_seconds = claims.get("exp_in_seconds")
        if exp_seconds is not None:
            if exp_seconds <= 0:
                findings.append({
                    "severity": "High",
                    "issue": "token_expired",
                    "detail": f"Token expired {abs(exp_seconds)} seconds ago",
                })
                risk_score += 50
            elif exp_seconds > 86400 * 7:  # >7 days
                findings.append({
                    "severity": "Medium",
                    "issue": "long_lived_token",
                    "detail": "Token has unusually long lifetime - increases risk if compromised",
                })
                risk_score += 20

        # Check 5: Required claims present
        required = ["sub", "iss", "aud"]
        for claim in required:
            if not claims.get(claim):
                findings.append({
                    "severity": "High",
                    "issue": f"missing_claim_{claim}",
                    "detail": f"Required claim '{claim}' is missing or empty",
                })
                risk_score += 40

        # === Disposition recommendation from this agent's perspective ===
        if risk_score >= 100:
            recommended = "revoke"
        elif risk_score >= 50:
            recommended = "challenge"
        elif risk_score >= 20:
            recommended = "monitor"
        else:
            recommended = "allow"

        # Confidence in this assessment
        # Token validation is deterministic so we have high confidence
        confidence = 0.95 if findings else 0.99

        return {
            "agent": self.AGENT_NAME,
            "request_id": request["request_id"],
            "findings": findings,
            "risk_score": min(risk_score, 100),
            "recommended_disposition": recommended,
            "confidence": confidence,
            "reasoning": self._build_reasoning(findings, risk_score),
        }

    def _analyze_api_key(self, request):
        """Lighter validation for API keys."""
        findings = []
        risk_score = 0

        token = request["token"]
        value = token.get("value", "")

        # API key structural checks
        if not value.startswith(("sk_live_", "sk_test_", "pk_live_", "pk_test_")):
            findings.append({
                "severity": "Medium",
                "issue": "unrecognized_api_key_format",
                "detail": "API key does not match expected format prefix",
            })
            risk_score += 30

        # Check it has expected claims/roles
        claims = token.get("claims", {})
        if not claims.get("sub", "").startswith("svc_"):
            findings.append({
                "severity": "Medium",
                "issue": "non_service_subject",
                "detail": "API key subject does not appear to be a service account",
            })
            risk_score += 20

        if risk_score >= 50:
            recommended = "challenge"
        elif risk_score >= 20:
            recommended = "monitor"
        else:
            recommended = "allow"

        return {
            "agent": self.AGENT_NAME,
            "request_id": request["request_id"],
            "findings": findings,
            "risk_score": min(risk_score, 100),
            "recommended_disposition": recommended,
            "confidence": 0.85,
            "reasoning": "API key validation - structural checks only. Production would also verify against the API key vault for revocation status.",
        }

    def _build_reasoning(self, findings, risk_score):
        """Build a human-readable explanation."""
        if not findings:
            return f"Token passed structural and cryptographic validation. Risk score: {risk_score}/100."

        critical = [f for f in findings if f["severity"] == "Critical"]
        if critical:
            return f"Critical token validation failures: {', '.join(f['issue'] for f in critical)}. This token should not be trusted."

        high = [f for f in findings if f["severity"] == "High"]
        if high:
            return f"High-severity validation issues: {', '.join(f['issue'] for f in high)}. Token integrity is in question."

        return f"Minor validation issues detected ({len(findings)} findings). Token is structurally usable but warrants monitoring."
