"""
Secrets & PII Detection Agent
==============================
Scans log files for exposed secrets, credentials, and PII.

Architecture:
  1. DETECT  - regex-based pattern matching (fast, deterministic)
  2. REASON  - AI validation layer to filter false positives (slow but smart)
  3. ACT     - tiered remediation: redact + notify based on severity
  4. LOG     - immutable audit trail of every decision

Demonstrates the hybrid intelligence pattern:
  Deterministic rules find candidates -> AI reasoning validates -> Tiered action

Usage:
    python3 agent.py                     # Full run with AI reasoning
    python3 agent.py --no-ai             # Pure regex (faster, more false positives)
    python3 agent.py --dry-run           # Show what it would do
    python3 agent.py --auto-approve      # No prompts (testing only)
    python3 agent.py --reset             # Clear all output and start fresh
"""

import os
import sys
import re
import json
import argparse
import shutil
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

from patterns import ALL_PATTERNS, get_redaction_for


# ===== Paths =====
BASE = Path(__file__).parent
LOG_DIR = BASE / "logs"
REDACTED_DIR = BASE / "redacted"
REPORT_DIR = BASE / "reports"
AUDIT_DIR = BASE / "audit"
SOC_INBOX = BASE / "audit" / "soc_inbox.json"
AUDIT_LOG = BASE / "audit" / "audit.jsonl"

for d in [REDACTED_DIR, REPORT_DIR, AUDIT_DIR]:
    d.mkdir(exist_ok=True)


# ===== Terminal colours =====
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"


def banner(text, c=C.CYAN):
    print(f"\n{c}{C.BOLD}{'=' * 72}\n{text}\n{'=' * 72}{C.RESET}")


def severity_badge(s):
    cols = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}
    return f"{cols.get(s, '')}{C.BOLD}[{s.upper()}]{C.RESET}"


# ===== Detection: Layer 1 - Regex =====

def detect_in_line(line, line_num, file_path):
    """Run all patterns against a single line. Returns list of finding dicts."""
    findings = []
    for pattern in ALL_PATTERNS:
        for match in pattern["regex"].finditer(line):
            matched_text = match.group(0)
            findings.append({
                "file": str(file_path.name),
                "line_number": line_num,
                "line_content": line.rstrip(),
                "pattern_name": pattern["name"],
                "category": pattern["category"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "regulatory": pattern["regulatory"],
                "validation_hint": pattern["validation_hint"],
                "matched_text": matched_text,
                "match_start": match.start(),
                "match_end": match.end(),
                "ai_validated": None,  # filled in by AI reasoning layer
                "ai_confidence": None,
                "ai_reasoning": None,
            })
    return findings


def scan_file(file_path):
    """Scan a single file for all patterns."""
    findings = []
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                findings.extend(detect_in_line(line, line_num, file_path))
    except Exception as e:
        print(f"  {C.RED}Error reading {file_path}: {e}{C.RESET}")
    return findings


# ===== Detection: Layer 2 - AI Reasoning =====
# This is the key architectural pattern - rules find candidates, AI validates.
# In production this would call Claude API. Here we simulate the reasoning
# locally so the demo runs without API setup, but the pattern is the same.

def ai_validate_finding(finding):
    """
    AI reasoning layer - validates whether a regex match is a real finding
    or a false positive based on context.

    In production: replace this with a real call to Claude API (or local LLM).
    The finding dict + validation_hint are exactly what you'd send as the prompt.

    Here we simulate it deterministically using context-aware rules so the
    demo runs without external dependencies.
    """
    pattern = finding["pattern_name"]
    line = finding["line_content"]
    matched = finding["matched_text"]

    # Default: trust the regex
    validated = True
    confidence = 0.85
    reasoning = "Pattern match passed default validation."

    # ----- False positive heuristics (the AI's reasoning) -----

    # Placeholder values
    placeholder_indicators = ["EXAMPLE", "REDACTED", "PLACEHOLDER", "YOUR_KEY", "***", "xxx", "FAKE", "DUMMY", "TEST_ONLY"]
    if any(ph.lower() in matched.lower() for ph in placeholder_indicators) and pattern not in ["aws_access_key", "private_key"]:
        validated = False
        confidence = 0.95
        reasoning = "Match contains placeholder indicator (EXAMPLE/REDACTED/YOUR_KEY etc.) - not a real credential."

    # Pattern-specific reasoning
    elif pattern == "credit_card":
        # Luhn algorithm validation
        digits = [int(d) for d in re.sub(r"[\s\-]", "", matched) if d.isdigit()]
        if len(digits) in (15, 16):
            checksum = 0
            for i, d in enumerate(reversed(digits)):
                if i % 2 == 1:
                    d *= 2
                    if d > 9:
                        d -= 9
                checksum += d
            if checksum % 10 != 0:
                validated = False
                confidence = 0.98
                reasoning = "Failed Luhn checksum validation - not a valid credit card number."
            else:
                confidence = 0.95
                reasoning = "Passed Luhn checksum - high confidence true positive."

    elif pattern == "email":
        # Role-based emails are typically not PII concerns
        role_prefixes = ["admin@", "support@", "noreply@", "no-reply@", "info@", "help@", "team@", "hello@", "contact@"]
        if any(matched.lower().startswith(rp) for rp in role_prefixes):
            validated = False
            confidence = 0.9
            reasoning = "Role-based email address (admin/support/etc) - not personal PII."

    elif pattern == "ipv4":
        # Internal IPs are usually not PII
        internal_ranges = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                          "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                          "127.", "169.254.", "0.0.0.0"]
        if any(matched.startswith(r) for r in internal_ranges):
            validated = False
            confidence = 0.85
            reasoning = "Internal/private IP range - not external PII concern under GDPR."

    elif pattern == "phone_us":
        # If line context suggests timestamps or version numbers, deprioritise
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["timestamp", "epoch", "uptime", "version", "build", "commit", "uuid"]):
            validated = False
            confidence = 0.7
            reasoning = "Surrounding context suggests this is a timestamp, version number, or identifier - not a phone number."

    elif pattern == "password_assignment":
        # Common false positive: password=[redacted], password=***, password=null
        fp_values = ["null", "none", "redacted", "***", "xxx", "removed", "hidden", "[set]", "<set>"]
        match_value = matched.lower()
        if any(fp in match_value for fp in fp_values):
            validated = False
            confidence = 0.95
            reasoning = "Password value is a placeholder (null/redacted/***/etc) - not a real credential."

    elif pattern == "private_key":
        confidence = 0.99
        reasoning = "Private key header is unambiguous - always a true positive."

    elif pattern == "aws_access_key":
        confidence = 0.97
        reasoning = "AWS access key format is highly specific - very low false positive rate."

    elif pattern == "stripe_key":
        if "sk_live_" in matched:
            confidence = 0.99
            reasoning = "Stripe live secret key - production credential, immediate action required."
        else:
            confidence = 0.95
            reasoning = "Stripe test key - still a credential, but lower production risk."

    return {
        "ai_validated": validated,
        "ai_confidence": round(confidence, 2),
        "ai_reasoning": reasoning,
    }


# ===== Action Layer: Redaction =====

def redact_file(file_path, findings_for_file, dry_run=False):
    """Create a redacted copy of the file with all validated findings replaced."""
    output_path = REDACTED_DIR / file_path.name
    redacted_count = 0

    # Group findings by line number, sorted by position descending so we redact right-to-left
    by_line = defaultdict(list)
    for f in findings_for_file:
        if f.get("ai_validated") and f.get("approved", True):
            by_line[f["line_number"]].append(f)

    with open(file_path, encoding="utf-8", errors="replace") as src:
        lines = src.readlines()

    for line_num, line_findings in by_line.items():
        if line_num > len(lines):
            continue
        line = lines[line_num - 1]
        # Sort findings on this line by position, right to left
        line_findings.sort(key=lambda x: -x["match_start"])
        for f in line_findings:
            redaction = get_redaction_for(f["pattern_name"], f["matched_text"])
            line = line[:f["match_start"]] + redaction + line[f["match_end"]:]
            redacted_count += 1
        lines[line_num - 1] = line

    if not dry_run:
        with open(output_path, "w") as out:
            out.writelines(lines)

    return output_path, redacted_count


# ===== Action Layer: SOC Notification =====

def notify_soc(severity, title, file_name, finding_count, sample_findings):
    """Append to the SOC inbox."""
    inbox = []
    if SOC_INBOX.exists():
        inbox = json.loads(SOC_INBOX.read_text())
    notification = {
        "id": f"SOC-{int(datetime.now().timestamp() * 1000)}",
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "title": title,
        "file": file_name,
        "finding_count": finding_count,
        "sample_findings": sample_findings[:3],
        "status": "open",
    }
    inbox.append(notification)
    SOC_INBOX.write_text(json.dumps(inbox, indent=2))
    return notification["id"]


# ===== Audit Trail =====

def audit(event):
    event["timestamp"] = datetime.now().isoformat()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


# ===== Main Agent Loop =====

class SecretsAgent:
    def __init__(self, use_ai=True, dry_run=False, auto_approve=False):
        self.use_ai = use_ai
        self.dry_run = dry_run
        self.auto_approve = auto_approve
        self.stats = Counter()

    def request_approval(self, file_name, finding_count, severity_summary):
        """Request approval for redaction action."""
        if self.dry_run or self.auto_approve:
            return True
        print(f"\n  {C.YELLOW}{C.BOLD}[APPROVAL REQUIRED]{C.RESET}")
        print(f"  Action: Redact {finding_count} validated finding(s) in {file_name}")
        print(f"  Severity breakdown: {severity_summary}")
        try:
            r = input(f"\n  Approve redaction? [y/N]: ").strip().lower()
        except EOFError:
            return False
        return r == "y"

    def process_file(self, file_path):
        banner(f"SCANNING: {file_path.name}", C.CYAN)

        # Layer 1: Regex detection
        raw_findings = scan_file(file_path)
        print(f"  Regex layer found {C.BOLD}{len(raw_findings)}{C.RESET} candidate finding(s).")
        self.stats["raw"] += len(raw_findings)

        if not raw_findings:
            print(f"  {C.GREEN}[CLEAN]{C.RESET} No matches in this file.")
            return

        # Layer 2: AI reasoning
        if self.use_ai:
            print(f"  {C.MAGENTA}Running AI validation layer...{C.RESET}")
            for f in raw_findings:
                result = ai_validate_finding(f)
                f.update(result)
            true_positives = [f for f in raw_findings if f["ai_validated"]]
            false_positives = [f for f in raw_findings if not f["ai_validated"]]
            print(f"  AI validated: {C.GREEN}{len(true_positives)} true positives{C.RESET}, "
                  f"{C.DIM}{len(false_positives)} filtered as false positives{C.RESET}")
            self.stats["true_positives"] += len(true_positives)
            self.stats["false_positives"] += len(false_positives)
        else:
            for f in raw_findings:
                f["ai_validated"] = True
                f["ai_confidence"] = None
                f["ai_reasoning"] = "AI layer disabled - not validated"
            true_positives = raw_findings
            self.stats["true_positives"] += len(true_positives)

        if not true_positives:
            print(f"  {C.GREEN}All matches were false positives - nothing to remediate.{C.RESET}")
            return

        # Show findings
        print(f"\n  {C.BOLD}Validated findings:{C.RESET}")
        sev_counts = Counter(f["severity"] for f in true_positives)
        for sev in ["Critical", "High", "Medium", "Low"]:
            if sev_counts.get(sev):
                print(f"    {severity_badge(sev)} {sev_counts[sev]}")

        # Show sample findings
        print(f"\n  {C.BOLD}Sample findings:{C.RESET}")
        for f in sorted(true_positives, key=lambda x: -{"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[x["severity"]])[:5]:
            shown_match = f["matched_text"][:30] + "..." if len(f["matched_text"]) > 30 else f["matched_text"]
            print(f"    {severity_badge(f['severity'])} {f['description']:30} L{f['line_number']:>4}: {C.DIM}{shown_match}{C.RESET}")
            if self.use_ai and f["ai_reasoning"]:
                print(f"      {C.DIM}AI: {f['ai_reasoning']} (confidence={f['ai_confidence']}){C.RESET}")

        # Tiered remediation decision
        max_severity = max(true_positives, key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[x["severity"]])["severity"]

        # Always notify SOC
        notif_id = notify_soc(
            severity=max_severity,
            title=f"Secrets/PII detected in {file_path.name}",
            file_name=file_path.name,
            finding_count=len(true_positives),
            sample_findings=[{
                "severity": f["severity"],
                "type": f["description"],
                "line": f["line_number"],
                "regulatory": f["regulatory"],
            } for f in true_positives],
        )
        print(f"\n  {C.GREEN}[AUTO]{C.RESET} SOC notified: {notif_id}")
        self.stats["soc_notifications"] += 1
        audit({
            "event": "soc_notified",
            "file": file_path.name,
            "notification_id": notif_id,
            "severity": max_severity,
            "finding_count": len(true_positives),
        })

        # Tiered redaction approach
        # All severities auto-redact - redaction is reversible (originals preserved on disk)
        # and SOC has been notified for awareness
        print(f"  {C.GREEN}[AUTO]{C.RESET} {max_severity} severity - auto-redacting (originals preserved, SOC notified).")
        self.stats["auto_redactions"] += 1

        # Execute redaction
        for f in true_positives:
            f["approved"] = True
        output_path, redacted_count = redact_file(file_path, true_positives, dry_run=self.dry_run)

        if self.dry_run:
            print(f"  {C.MAGENTA}[DRY RUN]{C.RESET} Would redact {redacted_count} occurrences -> {output_path}")
        else:
            print(f"  {C.GREEN}[OK]{C.RESET} Redacted {redacted_count} occurrences -> {output_path}")
            self.stats["redactions"] += redacted_count
            audit({
                "event": "file_redacted",
                "source": str(file_path),
                "output": str(output_path),
                "redacted_count": redacted_count,
            })

        return true_positives

    def run(self):
        banner("SECRETS & PII DETECTION AGENT", C.MAGENTA)
        mode_parts = []
        if self.use_ai: mode_parts.append("AI-validated")
        else: mode_parts.append("Rule-only")
        if self.dry_run: mode_parts.append("DRY RUN")
        if self.auto_approve: mode_parts.append("Auto-approve")
        print(f"  Mode: {C.BOLD}{' | '.join(mode_parts)}{C.RESET}")

        log_files = sorted(LOG_DIR.glob("*.log"))
        print(f"  Files to scan: {len(log_files)}")

        all_findings = []
        for f in log_files:
            file_findings = self.process_file(f)
            if file_findings:
                all_findings.extend(file_findings)

        # Summary
        banner("EXECUTION SUMMARY", C.MAGENTA)
        print(f"  Files scanned:           {len(log_files)}")
        print(f"  Raw regex matches:       {self.stats['raw']}")
        if self.use_ai:
            print(f"  Validated true positives: {self.stats['true_positives']}")
            print(f"  Filtered false positives: {self.stats['false_positives']}")
            if self.stats['raw']:
                fp_rate = self.stats['false_positives'] / self.stats['raw'] * 100
                print(f"  False positive rate:     {fp_rate:.1f}%")
        print(f"  SOC notifications sent:   {self.stats['soc_notifications']}")
        print(f"  Auto-redactions:          {self.stats['auto_redactions']}")
        print(f"  Approved redactions:      {self.stats['approved']}")
        print(f"  Rejected redactions:      {self.stats['rejected']}")
        if not self.dry_run:
            print(f"  Total values redacted:    {self.stats['redactions']}")

        # Generate HTML report
        if all_findings:
            generate_html_report(all_findings, self.stats, self.use_ai)
            print(f"\n  {C.CYAN}Report:    {REPORT_DIR}/findings_report.html{C.RESET}")
        print(f"  {C.DIM}Audit log: {AUDIT_LOG}{C.RESET}")
        print(f"  {C.DIM}SOC inbox: {SOC_INBOX}{C.RESET}")
        if not self.dry_run:
            print(f"  {C.DIM}Redacted:  {REDACTED_DIR}/{C.RESET}")
        print()


# ===== HTML Report =====

def generate_html_report(findings, stats, use_ai):
    sev_colors = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f39c12", "Low": "#27ae60"}
    sev_bg = {"Critical": "#fdedeb", "High": "#fdf2e9", "Medium": "#fef5e7", "Low": "#eafaf1"}

    counts = Counter(f["severity"] for f in findings)
    cat_counts = Counter(f["category"] for f in findings)

    # Group by file
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Secrets & PII Findings Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          max-width: 1200px; margin: 30px auto; padding: 20px; background: #f5f7fa; color: #2c3e50; }}
  h1 {{ color: #1a2533; border-bottom: 3px solid #2e75b6; padding-bottom: 10px; }}
  h2 {{ color: #1f4e79; margin-top: 35px; }}
  .summary {{ background: white; padding: 25px; border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 30px; }}
  .stats {{ display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px; }}
  .stat-card {{ flex: 1; min-width: 130px; padding: 18px; border-radius: 6px; text-align: center; }}
  .stat-num {{ font-size: 32px; font-weight: bold; }}
  .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
  .file-section {{ background: white; border-radius: 8px; padding: 22px;
                   margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.05); }}
  .file-title {{ font-size: 17px; font-weight: bold; color: #1a2533;
                 padding-bottom: 10px; border-bottom: 2px solid #ecf0f1; margin-bottom: 15px; }}
  .finding {{ padding: 12px; margin: 8px 0; border-left: 4px solid;
              background: #fafbfc; border-radius: 4px; }}
  .severity-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
                     color: white; font-weight: bold; font-size: 11px; text-transform: uppercase; }}
  .meta-row {{ font-size: 12px; color: #7f8c8d; margin: 6px 0; }}
  .matched {{ font-family: 'SF Mono', Menlo, monospace; background: #1a2533; color: #ecf0f1;
              padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
  .ai-info {{ background: #f4ecf7; border-left: 3px solid #8e44ad; padding: 8px 12px;
              margin-top: 8px; font-size: 12px; border-radius: 3px; }}
  .reg-tag {{ display: inline-block; background: #d6eaf8; color: #21618c;
              padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-right: 4px; }}
</style></head><body>
<h1>Secrets & PII Findings Report</h1>
<div class="summary">
  <p><strong>Generated:</strong> {datetime.now().strftime('%A, %B %d, %Y at %H:%M')}</p>
  <p><strong>AI validation layer:</strong> {"Enabled" if use_ai else "Disabled"}</p>
  <p><strong>Total validated findings:</strong> {len(findings)}</p>
  <div class="stats">"""

    for sev in ["Critical", "High", "Medium", "Low"]:
        c = counts.get(sev, 0)
        html += f"""
    <div class="stat-card" style="background: {sev_bg[sev]};">
      <div class="stat-num" style="color: {sev_colors[sev]};">{c}</div>
      <div class="stat-label" style="color: {sev_colors[sev]};">{sev}</div>
    </div>"""

    html += f"""
  </div>
  <p style="margin-top: 18px; color: #555;">
    <strong>Categories:</strong> 
    {' | '.join(f'{cat}: {ct}' for cat, ct in cat_counts.most_common())}
  </p>
</div>
<h2>Findings By File</h2>
"""

    for file_name, file_findings in sorted(by_file.items()):
        html += f"""<div class="file-section">
  <div class="file-title">{file_name} <span style="color: #95a5a6; font-weight: normal;">— {len(file_findings)} finding(s)</span></div>
"""
        for f in sorted(file_findings, key=lambda x: -{"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[x["severity"]]):
            reg_tags = ' '.join(f'<span class="reg-tag">{r}</span>' for r in f["regulatory"])
            ai_block = ""
            if use_ai and f.get("ai_reasoning"):
                ai_block = f"""<div class="ai-info"><strong>AI:</strong> {f['ai_reasoning']} <em>(confidence: {f['ai_confidence']})</em></div>"""

            shown_text = f["matched_text"][:60] + "..." if len(f["matched_text"]) > 60 else f["matched_text"]
            html += f"""
  <div class="finding" style="border-left-color: {sev_colors[f['severity']]};">
    <span class="severity-badge" style="background: {sev_colors[f['severity']]};">{f['severity']}</span>
    <strong style="margin-left: 8px;">{f['description']}</strong>
    <span style="color: #95a5a6; margin-left: 8px;">— Line {f['line_number']}</span>
    <div class="meta-row">Match: <span class="matched">{shown_text}</span></div>
    <div class="meta-row">Regulatory: {reg_tags}</div>
    {ai_block}
  </div>"""
        html += "</div>"

    html += "</body></html>"

    with open(REPORT_DIR / "findings_report.html", "w") as out:
        out.write(html)


# ===== Reset =====

def reset_environment():
    for d in [REDACTED_DIR, REPORT_DIR]:
        if d.exists():
            shutil.rmtree(d)
            d.mkdir()
    if SOC_INBOX.exists():
        SOC_INBOX.unlink()
    if AUDIT_LOG.exists():
        AUDIT_LOG.unlink()
    print(f"{C.GREEN}Environment reset.{C.RESET}")


# ===== CLI =====

def main():
    p = argparse.ArgumentParser(description="Secrets & PII Detection Agent")
    p.add_argument("--no-ai", action="store_true", help="Disable AI validation layer (faster, more false positives)")
    p.add_argument("--dry-run", action="store_true", help="Show what would happen without acting")
    p.add_argument("--auto-approve", action="store_true", help="Auto-approve all redactions (testing only)")
    p.add_argument("--reset", action="store_true", help="Clear all output and start fresh")
    args = p.parse_args()

    if args.reset:
        reset_environment()
        return

    agent = SecretsAgent(
        use_ai=not args.no_ai,
        dry_run=args.dry_run,
        auto_approve=args.auto_approve,
    )
    agent.run()


if __name__ == "__main__":
    main()
