"""
Detection Patterns Library
============================
Each pattern includes:
  - regex: the detection pattern
  - severity: Critical / High / Medium / Low
  - category: Secrets / PII / Custom
  - description: what it detects
  - regulatory: which frameworks treat this as a finding
  - validation_hint: helps the AI reasoning layer validate true positives
"""

import re

# ===== SECRETS / CREDENTIALS =====
SECRET_PATTERNS = [
    {
        "name": "aws_access_key",
        "regex": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "severity": "Critical",
        "category": "Secrets",
        "description": "AWS Access Key ID",
        "regulatory": ["PCI-DSS", "SOC 2", "NYDFS Part 500"],
        "validation_hint": "AWS keys start with AKIA (long-term) or ASIA (temporary). 20 chars total.",
    },
    {
        "name": "aws_secret_key",
        "regex": re.compile(r"\baws[_\-]?secret[_\-]?(access)?[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})\b", re.IGNORECASE),
        "severity": "Critical",
        "category": "Secrets",
        "description": "AWS Secret Access Key",
        "regulatory": ["PCI-DSS", "SOC 2", "NYDFS Part 500"],
        "validation_hint": "AWS secret keys are 40 base64 chars. Often appear after aws_secret_access_key=",
    },
    {
        "name": "github_token",
        "regex": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "severity": "Critical",
        "category": "Secrets",
        "description": "GitHub Personal Access Token",
        "regulatory": ["SOC 2", "Source Code Protection"],
        "validation_hint": "GitHub PATs start with ghp_ followed by 36 alphanumeric chars.",
    },
    {
        "name": "slack_token",
        "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "severity": "High",
        "category": "Secrets",
        "description": "Slack API Token",
        "regulatory": ["SOC 2"],
        "validation_hint": "Slack tokens start with xoxb- xoxp- xoxa- xoxr- or xoxs-",
    },
    {
        "name": "jwt_token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "severity": "High",
        "category": "Secrets",
        "description": "JSON Web Token (JWT)",
        "regulatory": ["GDPR", "SOC 2"],
        "validation_hint": "JWTs have 3 base64 sections separated by dots. Header always starts with eyJ.",
    },
    {
        "name": "private_key",
        "regex": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----"),
        "severity": "Critical",
        "category": "Secrets",
        "description": "Private Cryptographic Key",
        "regulatory": ["PCI-DSS", "SOC 2", "NYDFS Part 500", "DORA"],
        "validation_hint": "Private key headers are unambiguous. Always a true positive.",
    },
    {
        "name": "generic_api_key",
        "regex": re.compile(r"\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)['\"\s:=]+([A-Za-z0-9_\-]{20,})\b", re.IGNORECASE),
        "severity": "High",
        "category": "Secrets",
        "description": "Generic API Key or Access Token",
        "regulatory": ["SOC 2"],
        "validation_hint": "Field name suggests credential. Verify the value looks like a real token (high entropy, length 20+).",
    },
    {
        "name": "password_in_url",
        "regex": re.compile(r"\b[a-z]+://[^:\s]+:([^@\s]+)@[^\s]+", re.IGNORECASE),
        "severity": "Critical",
        "category": "Secrets",
        "description": "Password embedded in URL",
        "regulatory": ["PCI-DSS", "GDPR"],
        "validation_hint": "URL with user:password@host format. Always a true positive if password is non-trivial.",
    },
    {
        "name": "password_assignment",
        "regex": re.compile(r"\b(password|passwd|pwd)['\"\s:=]+['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE),
        "severity": "High",
        "category": "Secrets",
        "description": "Password value in plaintext",
        "regulatory": ["PCI-DSS", "GDPR", "NYDFS Part 500"],
        "validation_hint": "Watch for false positives - placeholder values like 'password=***' or 'password=REDACTED' are not real findings.",
    },
    {
        "name": "stripe_key",
        "regex": re.compile(r"\b(sk|pk)_(test|live)_[A-Za-z0-9]{24,}\b"),
        "severity": "Critical",
        "category": "Secrets",
        "description": "Stripe API Key",
        "regulatory": ["PCI-DSS"],
        "validation_hint": "Stripe keys are unambiguous. sk_live_ is most critical - production secret key.",
    },
]

# ===== PII =====
PII_PATTERNS = [
    {
        "name": "credit_card",
        "regex": re.compile(r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b"),
        "severity": "Critical",
        "category": "PII",
        "description": "Credit Card Number",
        "regulatory": ["PCI-DSS", "GDPR"],
        "validation_hint": "Validate using Luhn algorithm. Visa starts 4, MC starts 5, Amex starts 34/37, Discover starts 6011.",
    },
    {
        "name": "ssn",
        "regex": re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b"),
        "severity": "Critical",
        "category": "PII",
        "description": "US Social Security Number",
        "regulatory": ["GDPR", "NYDFS Part 500", "State Privacy Laws"],
        "validation_hint": "SSN format excludes invalid prefixes (000, 666, 900-999), middle 00, last 0000.",
    },
    {
        "name": "email",
        "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "severity": "Medium",
        "category": "PII",
        "description": "Email Address",
        "regulatory": ["GDPR"],
        "validation_hint": "Filter out role-based addresses (admin@, support@, no-reply@) - those are typically not PII.",
    },
    {
        "name": "phone_us",
        "regex": re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b"),
        "severity": "Medium",
        "category": "PII",
        "description": "US Phone Number",
        "regulatory": ["GDPR", "TCPA"],
        "validation_hint": "Watch for false positives - looks like timestamps, IDs, or version numbers (e.g. 408.123.4567 vs 408 123 4567).",
    },
    {
        "name": "ipv4",
        "regex": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        "severity": "Low",
        "category": "PII",
        "description": "IPv4 Address",
        "regulatory": ["GDPR (PII under EU interpretation)"],
        "validation_hint": "Internal IPs (10.x, 192.168.x, 172.16-31.x) are usually not PII concerns. External IPs may be PII under GDPR.",
    },
    {
        "name": "iban",
        "regex": re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"),
        "severity": "Critical",
        "category": "PII",
        "description": "IBAN (International Bank Account Number)",
        "regulatory": ["GDPR", "PCI-DSS-adjacent"],
        "validation_hint": "IBAN starts with 2-letter country code, 2 check digits, then up to 30 alphanumeric chars.",
    },
    {
        "name": "passport_us",
        "regex": re.compile(r"\b(?:passport|passport[_\s]?(?:no|number|num)|pp[_\s]?no)['\":\s=]+[A-Z0-9]{6,9}\b", re.IGNORECASE),
        "severity": "Critical",
        "category": "PII",
        "description": "Passport Number (context-tagged)",
        "regulatory": ["GDPR", "Identity Theft Protection Acts"],
        "validation_hint": "Only flag when context word (passport, pp_no) is present to reduce false positives.",
    },
]

# ===== CUSTOM PATTERNS - configurable =====
CUSTOM_PATTERNS = [
    {
        "name": "internal_employee_id",
        "regex": re.compile(r"\bEMP-[0-9]{6}\b"),
        "severity": "Medium",
        "category": "Custom",
        "description": "Internal Employee ID",
        "regulatory": ["GDPR", "Internal Policy"],
        "validation_hint": "Custom format for this organisation - EMP- followed by 6 digits.",
    },
    {
        "name": "customer_account_id",
        "regex": re.compile(r"\bCUST-[A-Z0-9]{8,12}\b"),
        "severity": "High",
        "category": "Custom",
        "description": "Customer Account Identifier",
        "regulatory": ["GDPR", "Customer Privacy"],
        "validation_hint": "Customer IDs link to PII - treat with care.",
    },
]

ALL_PATTERNS = SECRET_PATTERNS + PII_PATTERNS + CUSTOM_PATTERNS


def get_redaction_for(pattern_name, original_value):
    """Generate appropriate redaction text preserving some structure."""
    redactions = {
        "credit_card": f"****-****-****-{original_value[-4:]}" if len(original_value) >= 4 else "[REDACTED-CC]",
        "ssn": f"***-**-{original_value[-4:]}" if len(original_value) >= 4 else "[REDACTED-SSN]",
        "email": "[REDACTED-EMAIL]",
        "phone_us": "[REDACTED-PHONE]",
        "ipv4": "[REDACTED-IP]",
    }
    return redactions.get(pattern_name, f"[REDACTED-{pattern_name.upper()}]")
