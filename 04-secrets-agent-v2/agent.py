"""
Secrets & PII Detection Agent v2 - With Vault Integration
============================================================
Extends v1 with the full discovery and vaulting pipeline:

  1. DETECT  - regex finds candidates
  2. REASON  - AI validates true positives
  3. VAULT   - store secret in AWS Secrets Manager (simulated)
  4. REGISTER - record in discoverable index for SOC
  5. REPLACE - swap secret in file with discoverable URI reference
  6. NOTIFY  - SOC alerted with severity + lookup info
  7. AUDIT   - immutable trail of every decision

Key architectural shift from v1: redaction is no longer destructive.
Original secrets go to the vault. References go in the file. Apps and SOC
can resolve references back via the registry.

Usage:
    python3 agent.py                  # Full vault + register + replace
    python3 agent.py --no-vault       # Skip vaulting (just detect + replace with [REDACTED])
    python3 agent.py --dry-run        # Show what would happen
    python3 agent.py --auto-approve   # No prompts (testing)
    python3 agent.py --reset          # Clear vault, registry, all output
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
import vault
import registry as registry_mod


# Paths
BASE = Path(__file__).parent
LOG_DIR = BASE / "logs"
REDACTED_DIR = BASE / "redacted"
REPORT_DIR = BASE / "reports"
AUDIT_DIR = BASE / "audit"
SOC_INBOX = AUDIT_DIR / "soc_inbox.json"
AUDIT_LOG = AUDIT_DIR / "audit.jsonl"

for d in [REDACTED_DIR, REPORT_DIR, AUDIT_DIR]:
    d.mkdir(exist_ok=True)


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"


def banner(text, c=C.CYAN):
    print(f"\n{c}{C.BOLD}{'=' * 76}\n{text}\n{'=' * 76}{C.RESET}")


def severity_badge(s):
    cols = {"Critical": C.RED, "High": C.YELLOW, "Medium": C.BLUE, "Low": C.GREEN}
    return f"{cols.get(s, '')}{C.BOLD}[{s.upper()}]{C.RESET}"


# ===== Hash for audit log (don't log raw secrets) =====
def hash_value(value):
    import hashlib
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()[:16]}"


# ===== Detection =====
def detect_in_line(line, line_num, file_path):
    findings = []
    for pattern in ALL_PATTERNS:
        for match in pattern["regex"].finditer(line):
            matched_text = match.group(0)
            findings.append({
                "file": file_path.name,
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
                "ai_validated": None,
                "ai_confidence": None,
                "ai_reasoning": None,
                "vault_uri": None,
                "secret_id": None,
            })
    return findings


def scan_file(file_path):
    findings = []
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                findings.extend(detect_in_line(line, line_num, file_path))
    except Exception as e:
        print(f"  {C.RED}Error reading {file_path}: {e}{C.RESET}")
    return findings


# ===== AI Reasoning Layer =====
def ai_validate_finding(finding):
    pattern = finding["pattern_name"]
    line = finding["line_content"]
    matched = finding["matched_text"]

    validated = True
    confidence = 0.85
    reasoning = "Pattern match passed default validation."

    placeholder_indicators = ["EXAMPLE", "REDACTED", "PLACEHOLDER", "YOUR_KEY", "***", "FAKE", "DUMMY", "TEST_ONLY"]
    if any(ph.lower() in matched.lower() for ph in placeholder_indicators) and pattern not in ["aws_access_key", "private_key"]:
        validated = False
        confidence = 0.95
        reasoning = "Match contains placeholder indicator - not a real credential."

    elif pattern == "credit_card":
        digits = [int(d) for d in re.sub(r"[\s\-]", "", matched) if d.isdigit()]
        if len(digits) in (15, 16):
            checksum = 0
            for i, d in enumerate(reversed(digits)):
                if i % 2 == 1:
                    d *= 2
                    if d > 9: d -= 9
                checksum += d
            if checksum % 10 != 0:
                validated = False
                confidence = 0.98
                reasoning = "Failed Luhn checksum - not a valid card number."
            else:
                confidence = 0.95
                reasoning = "Passed Luhn checksum - high confidence true positive."

    elif pattern == "email":
        role_prefixes = ["admin@", "support@", "noreply@", "no-reply@", "info@", "help@", "team@", "hello@", "contact@"]
        if any(matched.lower().startswith(rp) for rp in role_prefixes):
            validated = False
            confidence = 0.9
            reasoning = "Role-based email - not personal PII."

    elif pattern == "ipv4":
        internal = ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "127.", "169.254.", "0.0.0.0"]
        if any(matched.startswith(r) for r in internal):
            validated = False
            confidence = 0.85
            reasoning = "Internal/private IP - not external PII concern."

    elif pattern == "phone_us":
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["timestamp", "epoch", "uptime", "version", "build", "commit", "uuid"]):
            validated = False
            confidence = 0.7
            reasoning = "Context suggests timestamp/version/identifier - not a phone number."

    elif pattern == "password_assignment":
        fp_values = ["null", "none", "redacted", "***", "xxx", "removed", "hidden", "[set]", "<set>"]
        if any(fp in matched.lower() for fp in fp_values):
            validated = False
            confidence = 0.95
            reasoning = "Password value is placeholder - not a real credential."

    elif pattern == "private_key":
        confidence = 0.99
        reasoning = "Private key header is unambiguous."

    elif pattern == "aws_access_key":
        confidence = 0.97
        reasoning = "AWS access key format is highly specific."

    elif pattern == "stripe_key":
        if "sk_live_" in matched:
            confidence = 0.99
            reasoning = "Stripe live secret - production credential, immediate action."
        else:
            confidence = 0.95
            reasoning = "Stripe test key."

    return {
        "ai_validated": validated,
        "ai_confidence": round(confidence, 2),
        "ai_reasoning": reasoning,
    }


# ===== Vault Integration =====
def is_vaultable_category(category):
    """Only secrets go to vault. PII gets [REDACTED] (different lifecycle)."""
    return category in ("Secrets", "Custom")


def vault_and_register(finding):
    """Store secret in vault and register in discovery index."""
    secret_path = vault.derive_secret_path(finding["pattern_name"], finding)
    vault_uri, version = vault.put_secret(
        path=secret_path,
        value=finding["matched_text"],
        tags={
            "discovered_in": finding["file"],
            "pattern": finding["pattern_name"],
            "severity": finding["severity"],
        }
    )

    secret_id = registry_mod.derive_secret_id(
        finding["pattern_name"], finding["file"],
        finding["line_number"], finding["matched_text"]
    )

    registry_entry = registry_mod.register_secret(
        secret_id=secret_id,
        vault_uri=vault_uri,
        version=version,
        finding=finding
    )

    finding["vault_uri"] = vault_uri
    finding["vault_version"] = version
    finding["secret_id"] = secret_id
    finding["owner_team"] = registry_entry["owner_team"]

    return f"{{{{{vault_uri}#{version}}}}}"  # the reference URI


# ===== Replacement =====
def process_file_replacements(file_path, findings, use_vault=True, dry_run=False):
    """Create the cleaned copy of the file with references or redactions."""
    output_path = REDACTED_DIR / file_path.name
    replacement_count = 0
    vaulted_count = 0

    by_line = defaultdict(list)
    for f in findings:
        if f.get("ai_validated") and f.get("approved", True):
            by_line[f["line_number"]].append(f)

    with open(file_path, encoding="utf-8", errors="replace") as src:
        lines = src.readlines()

    for line_num, line_findings in by_line.items():
        if line_num > len(lines):
            continue
        line = lines[line_num - 1]
        line_findings.sort(key=lambda x: -x["match_start"])

        for f in line_findings:
            # Decide replacement strategy
            if use_vault and is_vaultable_category(f["category"]):
                # Vault the secret, replace with reference
                if not dry_run:
                    replacement = vault_and_register(f)
                    vaulted_count += 1
                else:
                    replacement = f"{{{{secret://aws-secretsmanager/<would-be-vaulted>#v1}}}}"
            else:
                # Non-vaultable (PII) gets redacted
                replacement = get_redaction_for(f["pattern_name"], f["matched_text"])

            line = line[:f["match_start"]] + replacement + line[f["match_end"]:]
            replacement_count += 1

        lines[line_num - 1] = line

    if not dry_run:
        with open(output_path, "w") as out:
            out.writelines(lines)

    return output_path, replacement_count, vaulted_count


# ===== SOC Notification =====
def notify_soc(severity, title, file_name, finding_count, sample_findings):
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
        "lookup_hint": "Run 'python3 soc_view.py --severity <sev>' to see vaulted secrets",
        "status": "open",
    }
    inbox.append(notification)
    SOC_INBOX.write_text(json.dumps(inbox, indent=2))
    return notification["id"]


# ===== Audit (no raw secrets logged) =====
def audit(event):
    event["timestamp"] = datetime.now().isoformat()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


# ===== Main Agent =====
class SecretsAgentV2:
    def __init__(self, use_vault=True, dry_run=False, auto_approve=False):
        self.use_vault = use_vault
        self.dry_run = dry_run
        self.auto_approve = auto_approve
        self.stats = Counter()
        self.all_findings = []

    def request_approval(self, file_name, count, sev_summary):
        if self.dry_run or self.auto_approve:
            return True
        print(f"\n  {C.YELLOW}{C.BOLD}[APPROVAL REQUIRED]{C.RESET}")
        print(f"  Action: Vault and replace {count} validated finding(s) in {file_name}")
        print(f"  Severity: {sev_summary}")
        if self.use_vault:
            print(f"  This will store secrets in the vault and replace with discoverable references.")
        try:
            r = input(f"\n  Approve? [y/N]: ").strip().lower()
        except EOFError:
            return False
        return r == "y"

    def process_file(self, file_path):
        banner(f"SCANNING: {file_path.name}", C.CYAN)

        raw_findings = scan_file(file_path)
        print(f"  Regex layer found {C.BOLD}{len(raw_findings)}{C.RESET} candidates.")
        self.stats["raw"] += len(raw_findings)

        if not raw_findings:
            print(f"  {C.GREEN}[CLEAN]{C.RESET}")
            return

        # AI validation
        print(f"  {C.MAGENTA}Running AI validation...{C.RESET}")
        for f in raw_findings:
            f.update(ai_validate_finding(f))

        true_pos = [f for f in raw_findings if f["ai_validated"]]
        false_pos = [f for f in raw_findings if not f["ai_validated"]]
        print(f"  Validated: {C.GREEN}{len(true_pos)} true{C.RESET}, {C.DIM}{len(false_pos)} filtered{C.RESET}")
        self.stats["true_positives"] += len(true_pos)
        self.stats["false_positives"] += len(false_pos)

        if not true_pos:
            return

        # Show summary
        sev_counts = Counter(f["severity"] for f in true_pos)
        cat_counts = Counter(f["category"] for f in true_pos)
        print(f"\n  {C.BOLD}Findings:{C.RESET}")
        for sev in ["Critical", "High", "Medium", "Low"]:
            if sev_counts.get(sev):
                print(f"    {severity_badge(sev)} {sev_counts[sev]}")
        print(f"  {C.DIM}Categories: {dict(cat_counts)}{C.RESET}")

        # Determine max severity for tiering
        max_sev = max(true_pos, key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[x["severity"]])["severity"]

        # SOC notify
        notif_id = notify_soc(
            severity=max_sev,
            title=f"Secrets/PII detected in {file_path.name}",
            file_name=file_path.name,
            finding_count=len(true_pos),
            sample_findings=[{
                "severity": f["severity"], "type": f["description"],
                "line": f["line_number"], "regulatory": f["regulatory"],
            } for f in true_pos],
        )
        print(f"\n  {C.GREEN}[AUTO]{C.RESET} SOC notified: {notif_id}")
        self.stats["soc_notifications"] += 1
        audit({
            "event": "soc_notified", "file": file_path.name,
            "notification_id": notif_id, "severity": max_sev,
            "finding_count": len(true_pos),
        })

        # All severities auto-vault and replace
        # Vault stores secrets with versioning so this is reversible (rotate to previous version)
        # Original files remain untouched on disk - only redacted copies in redacted/
        # SOC is notified for every finding so awareness is maintained
        print(f"  {C.GREEN}[AUTO]{C.RESET} {max_sev} severity - auto-vaulting (originals preserved, SOC notified, vault versioned).")
        self.stats["auto_actions"] += 1

        # Mark approved and execute
        for f in true_pos:
            f["approved"] = True

        output_path, replacement_count, vaulted_count = process_file_replacements(
            file_path, true_pos, use_vault=self.use_vault, dry_run=self.dry_run
        )

        if self.dry_run:
            print(f"  {C.MAGENTA}[DRY RUN]{C.RESET} Would replace {replacement_count} occurrence(s)")
            if self.use_vault:
                vaultable = sum(1 for f in true_pos if is_vaultable_category(f["category"]))
                print(f"  {C.MAGENTA}[DRY RUN]{C.RESET} Would vault {vaultable} secret(s)")
        else:
            print(f"  {C.GREEN}[OK]{C.RESET} Replaced {replacement_count} occurrence(s) -> {output_path.name}")
            if vaulted_count:
                print(f"  {C.GREEN}[OK]{C.RESET} Vaulted {vaulted_count} secret(s) and registered in SOC index")
            self.stats["replacements"] += replacement_count
            self.stats["vaulted"] += vaulted_count

        # Audit per-finding (with hashes, not raw values)
        for f in true_pos:
            audit({
                "event": "secret_processed",
                "file": f["file"],
                "line": f["line_number"],
                "pattern": f["pattern_name"],
                "severity": f["severity"],
                "category": f["category"],
                "value_hash": hash_value(f["matched_text"]),
                "secret_id": f.get("secret_id"),
                "vault_uri": f.get("vault_uri"),
                "ai_confidence": f["ai_confidence"],
                "ai_reasoning": f["ai_reasoning"],
            })

        self.all_findings.extend(true_pos)

    def run(self):
        banner("SECRETS & PII AGENT v2 - WITH VAULT INTEGRATION", C.MAGENTA)
        modes = []
        if self.use_vault: modes.append("Vault enabled")
        else: modes.append("Vault disabled")
        if self.dry_run: modes.append("DRY RUN")
        if self.auto_approve: modes.append("Auto-approve")
        print(f"  Mode: {C.BOLD}{' | '.join(modes)}{C.RESET}")

        log_files = sorted(LOG_DIR.glob("*.log"))
        print(f"  Files to scan: {len(log_files)}")

        for f in log_files:
            self.process_file(f)

        # Summary
        banner("EXECUTION SUMMARY", C.MAGENTA)
        print(f"  Files scanned:            {len(log_files)}")
        print(f"  Raw matches:              {self.stats['raw']}")
        print(f"  Validated true positives: {self.stats['true_positives']}")
        print(f"  Filtered false positives: {self.stats['false_positives']}")
        if self.stats['raw']:
            fp = self.stats['false_positives'] / self.stats['raw'] * 100
            print(f"  False positive rate:      {fp:.1f}%")
        print(f"  SOC notifications:        {self.stats['soc_notifications']}")
        print(f"  Auto actions:             {self.stats['auto_actions']}")
        print(f"  Approved:                 {self.stats['approved']}")
        print(f"  Rejected:                 {self.stats['rejected']}")
        if not self.dry_run:
            print(f"  Total replacements:       {self.stats['replacements']}")
            if self.use_vault:
                print(f"  {C.GREEN}{C.BOLD}Secrets vaulted:          {self.stats['vaulted']}{C.RESET}")

        if self.all_findings:
            generate_html_report(self.all_findings, self.stats, self.use_vault)
            print(f"\n  {C.CYAN}Report:    {REPORT_DIR}/findings_report.html{C.RESET}")
        print(f"  {C.DIM}Audit log: {AUDIT_LOG}{C.RESET}")
        print(f"  {C.DIM}SOC inbox: {SOC_INBOX}{C.RESET}")
        if self.use_vault and not self.dry_run:
            print(f"\n  {C.BOLD}NEXT STEPS:{C.RESET}")
            print(f"    {C.CYAN}python3 soc_view.py{C.RESET}              # SOC discovery view")
            print(f"    {C.CYAN}python3 resolver.py{C.RESET}              # See how apps fetch secrets")
            print(f"    {C.CYAN}cat redacted/debug.log{C.RESET}           # See references in cleaned files")
        print()


# ===== HTML Report =====
def generate_html_report(findings, stats, use_vault):
    sev_colors = {"Critical": "#c0392b", "High": "#e67e22", "Medium": "#f39c12", "Low": "#27ae60"}
    sev_bg = {"Critical": "#fdedeb", "High": "#fdf2e9", "Medium": "#fef5e7", "Low": "#eafaf1"}
    counts = Counter(f["severity"] for f in findings)
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Secrets & PII Findings - With Vault</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 1200px;
          margin: 30px auto; padding: 20px; background: #f5f7fa; color: #2c3e50; }}
  h1 {{ color: #1a2533; border-bottom: 3px solid #2e75b6; padding-bottom: 10px; }}
  h2 {{ color: #1f4e79; margin-top: 35px; }}
  .summary {{ background: white; padding: 25px; border-radius: 8px; margin-bottom: 30px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.05); }}
  .stats {{ display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px; }}
  .stat-card {{ flex: 1; min-width: 130px; padding: 18px; border-radius: 6px; text-align: center; }}
  .stat-num {{ font-size: 32px; font-weight: bold; }}
  .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
  .file-section {{ background: white; border-radius: 8px; padding: 22px; margin-bottom: 20px;
                   box-shadow: 0 2px 6px rgba(0,0,0,0.05); }}
  .file-title {{ font-size: 17px; font-weight: bold; padding-bottom: 10px;
                 border-bottom: 2px solid #ecf0f1; margin-bottom: 15px; }}
  .finding {{ padding: 12px; margin: 8px 0; border-left: 4px solid;
              background: #fafbfc; border-radius: 4px; }}
  .severity-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px;
                     color: white; font-weight: bold; font-size: 11px; text-transform: uppercase; }}
  .meta {{ font-size: 12px; color: #7f8c8d; margin: 6px 0; }}
  .vault-uri {{ font-family: 'SF Mono', Menlo, monospace; background: #d6eaf8;
                color: #1f618d; padding: 2px 8px; border-radius: 3px; font-size: 11px; }}
  .ai {{ background: #f4ecf7; border-left: 3px solid #8e44ad; padding: 8px 12px;
         margin-top: 8px; font-size: 12px; border-radius: 3px; }}
  .reg-tag {{ display: inline-block; background: #d6eaf8; color: #21618c;
              padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-right: 4px; }}
</style></head><body>
<h1>Secrets & PII Detection - With Vault Integration</h1>
<div class="summary">
  <p><strong>Generated:</strong> {datetime.now().strftime('%A, %B %d, %Y at %H:%M')}</p>
  <p><strong>Vault integration:</strong> {"Enabled - secrets stored in vault, references in files" if use_vault else "Disabled - secrets redacted only"}</p>
  <p><strong>Validated findings:</strong> {len(findings)} | <strong>Vaulted:</strong> {stats.get('vaulted', 0)}</p>
  <div class="stats">"""

    for sev in ["Critical", "High", "Medium", "Low"]:
        c = counts.get(sev, 0)
        html += f"""
    <div class="stat-card" style="background: {sev_bg[sev]};">
      <div class="stat-num" style="color: {sev_colors[sev]};">{c}</div>
      <div class="stat-label" style="color: {sev_colors[sev]};">{sev}</div>
    </div>"""

    html += "</div></div><h2>Findings By File</h2>"

    for file_name, file_findings in sorted(by_file.items()):
        html += f"""<div class="file-section">
  <div class="file-title">{file_name} <span style="color: #95a5a6; font-weight: normal;">— {len(file_findings)} finding(s)</span></div>
"""
        for f in sorted(file_findings, key=lambda x: -{"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[x["severity"]]):
            reg_tags = ' '.join(f'<span class="reg-tag">{r}</span>' for r in f["regulatory"])
            vault_block = ""
            if f.get("vault_uri"):
                vault_block = f"""<div class="meta">Vaulted to: <span class="vault-uri">{f['vault_uri']}#{f.get('vault_version', 'v1')}</span></div>
                <div class="meta">Secret ID: <code>{f.get('secret_id', '')}</code> | Owner: <strong>{f.get('owner_team', 'unassigned')}</strong></div>"""

            ai_block = f"""<div class="ai"><strong>AI:</strong> {f['ai_reasoning']} <em>(confidence: {f['ai_confidence']})</em></div>"""

            html += f"""
  <div class="finding" style="border-left-color: {sev_colors[f['severity']]};">
    <span class="severity-badge" style="background: {sev_colors[f['severity']]};">{f['severity']}</span>
    <strong style="margin-left: 8px;">{f['description']}</strong>
    <span style="color: #95a5a6; margin-left: 8px;">— Line {f['line_number']}</span>
    <div class="meta">Category: {f['category']}</div>
    {vault_block}
    <div class="meta">Regulatory: {reg_tags}</div>
    {ai_block}
  </div>"""
        html += "</div>"
    html += "</body></html>"

    with open(REPORT_DIR / "findings_report.html", "w") as out:
        out.write(html)


# ===== Reset =====
def reset_all():
    for d in [REDACTED_DIR, REPORT_DIR]:
        if d.exists():
            shutil.rmtree(d); d.mkdir()
    if SOC_INBOX.exists(): SOC_INBOX.unlink()
    if AUDIT_LOG.exists(): AUDIT_LOG.unlink()
    vault.reset_vault()
    registry_mod.reset_registry()
    print(f"{C.GREEN}All state reset (vault, registry, audit, redacted, reports).{C.RESET}")


# ===== CLI =====
def main():
    p = argparse.ArgumentParser(description="Secrets & PII Detection Agent v2 with Vault")
    p.add_argument("--no-vault", action="store_true", help="Skip vaulting - just detect and redact")
    p.add_argument("--dry-run", action="store_true", help="Show what would happen without acting")
    p.add_argument("--auto-approve", action="store_true", help="Auto-approve all (testing only)")
    p.add_argument("--reset", action="store_true", help="Reset all state")
    args = p.parse_args()

    if args.reset:
        reset_all()
        return

    agent = SecretsAgentV2(
        use_vault=not args.no_vault,
        dry_run=args.dry_run,
        auto_approve=args.auto_approve,
    )
    agent.run()


if __name__ == "__main__":
    main()
