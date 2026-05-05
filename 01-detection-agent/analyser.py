"""
Security Log Analyser Agent
============================
Reads security log files, identifies anomalous patterns,
scores findings by severity, and generates an HTML risk report.

Usage:
    python3 analyser.py
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

# === CONFIGURATION ===
LOG_DIR = Path(__file__).parent / "logs"
REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# Thresholds for detection
FAILED_LOGIN_THRESHOLD = 5  # Failed logins from same source in short window
AFTER_HOURS_START = 22       # 10 PM
AFTER_HOURS_END = 6          # 6 AM
LARGE_TRANSFER_BYTES = 1_000_000_000  # 1 GB outbound
PORT_SCAN_THRESHOLD = 10     # Distinct ports from one source

# Known bad IPs / suspicious indicators
KNOWN_BAD_IPS = {
    "185.220.101.45": "Tor exit node - frequently associated with attacks",
    "45.142.214.89": "Reported botnet C2 infrastructure",
    "194.165.16.118": "Malware delivery infrastructure",
    "91.243.59.27": "Known scanner/reconnaissance source",
}

CRYPTO_MINING_INDICATORS = ["xmr-pool", "minexmr", "monero", "stratum+tcp", ":3333", ":4444", ":7777"]


# === FINDING DATA STRUCTURE ===
class Finding:
    def __init__(self, severity, category, title, description, evidence, recommendation):
        self.severity = severity  # Critical, High, Medium, Low
        self.category = category
        self.title = title
        self.description = description
        self.evidence = evidence  # list of log lines
        self.recommendation = recommendation
        self.timestamp = datetime.now().isoformat()

    def severity_score(self):
        return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[self.severity]


# === DETECTION FUNCTIONS ===

def parse_log_timestamp(line):
    """Extract timestamp from log line. Returns datetime or None."""
    match = re.match(r"^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})", line)
    if match:
        try:
            year = datetime.now().year
            ts_str = f"{year} {match.group(1)} {match.group(2)} {match.group(3)}:{match.group(4)}:{match.group(5)}"
            return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    return None


def detect_brute_force(auth_lines):
    """Detect brute force SSH attacks - many failed logins from same source."""
    findings = []
    failures_by_ip = defaultdict(list)

    for line in auth_lines:
        match = re.search(r"Failed password for (\S+) from ([\d.]+)", line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            ts = parse_log_timestamp(line)
            if ts:
                failures_by_ip[ip].append((ts, user, line.strip()))

    for ip, attempts in failures_by_ip.items():
        if len(attempts) >= FAILED_LOGIN_THRESHOLD:
            # Check time window - all within an hour?
            attempts.sort()
            window = (attempts[-1][0] - attempts[0][0]).total_seconds()
            unique_users = set(a[1] for a in attempts)
            evidence = [a[2] for a in attempts[:5]] + [f"... and {len(attempts)-5} more attempts"]

            severity = "Critical" if len(attempts) > 20 else "High"
            ip_context = KNOWN_BAD_IPS.get(ip, "")
            desc = (f"Detected {len(attempts)} failed login attempts from {ip} "
                    f"targeting {len(unique_users)} different usernames over {int(window/60)} minutes.")
            if ip_context:
                desc += f" Source IP context: {ip_context}."

            findings.append(Finding(
                severity=severity,
                category="Authentication Attack",
                title=f"Brute force SSH attack from {ip}",
                description=desc,
                evidence=evidence,
                recommendation=("Block source IP at the firewall immediately. "
                               "Verify no successful login from this IP. "
                               "Review SSH configuration: enforce key-based auth only, "
                               "disable root login, enable fail2ban or equivalent.")
            ))

    return findings


def detect_brute_force_success(auth_lines):
    """Detect successful login from IP that just had many failures - account compromise."""
    findings = []
    failures_by_ip = defaultdict(list)
    successes_by_ip = defaultdict(list)

    for line in auth_lines:
        ts = parse_log_timestamp(line)
        if not ts:
            continue
        fail = re.search(r"Failed password for \S+ from ([\d.]+)", line)
        if fail:
            failures_by_ip[fail.group(1)].append(ts)
        success = re.search(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)", line)
        if success:
            successes_by_ip[success.group(2)].append((ts, success.group(1), line.strip()))

    for ip, successes in successes_by_ip.items():
        if ip in failures_by_ip and len(failures_by_ip[ip]) >= FAILED_LOGIN_THRESHOLD:
            for s_ts, user, s_line in successes:
                # Was there a successful login soon after many failures?
                recent_fails = [f for f in failures_by_ip[ip] if 0 <= (s_ts - f).total_seconds() <= 3600]
                if len(recent_fails) >= FAILED_LOGIN_THRESHOLD:
                    findings.append(Finding(
                        severity="Critical",
                        category="Account Compromise",
                        title=f"Successful login after brute force: {user} from {ip}",
                        description=(f"User '{user}' successfully authenticated from {ip} after "
                                     f"{len(recent_fails)} failed attempts within the preceding hour. "
                                     f"This is a strong indicator of credential compromise."),
                        evidence=[s_line],
                        recommendation=("INCIDENT RESPONSE: Treat as confirmed compromise. "
                                       "Immediately disable the affected account, force password reset, "
                                       "review all actions taken under this account since the login, "
                                       "and check for persistence mechanisms.")
                    ))
    return findings


def detect_after_hours_admin(auth_lines):
    """Detect sudo/root activity outside business hours."""
    findings = []
    for line in auth_lines:
        ts = parse_log_timestamp(line)
        if not ts:
            continue
        if ts.hour >= AFTER_HOURS_START or ts.hour < AFTER_HOURS_END:
            sudo_match = re.search(r"sudo\[\d+\]:\s+(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=root\s*;\s*COMMAND=(.+)", line)
            if sudo_match:
                user = sudo_match.group(1)
                command = sudo_match.group(2)
                # Filter out auto-runs of softwareupdate etc
                if "softwareupdate -l" in command:
                    continue
                findings.append(Finding(
                    severity="Medium",
                    category="After-Hours Privilege Use",
                    title=f"Sudo to root by {user} at {ts.strftime('%H:%M')} ({ts.strftime('%a')})",
                    description=(f"User '{user}' executed a privileged command at {ts.strftime('%H:%M')} "
                                f"on {ts.strftime('%A')} - outside normal business hours."),
                    evidence=[line.strip()],
                    recommendation=("Verify this activity was authorised. Contact the user to confirm. "
                                   "If unauthorised, treat as potential account compromise.")
                ))
    return findings


def detect_suspicious_commands(auth_lines):
    """Detect commands that strongly indicate malicious activity."""
    findings = []
    suspicious_patterns = [
        (r"curl\s+.*\|\s*bash", "Critical", "Remote code execution via curl pipe to bash"),
        (r"wget\s+.*\|\s*sh", "Critical", "Remote code execution via wget pipe to sh"),
        (r"dscl\s+\.\s+-append\s+/Groups/admin", "Critical", "Privilege escalation: adding user to admin group"),
        (r"dscl\s+\.\s+-create\s+/Users/", "High", "User creation via dscl"),
        (r"/tmp/\.\w+", "High", "Execution from hidden file in /tmp"),
        (r"chmod\s+777", "Medium", "Overly permissive chmod"),
        (r"nc\s+-l", "High", "Netcat listener (potential backdoor)"),
        (r"base64\s+.*\|\s*bash", "Critical", "Obfuscated remote execution"),
    ]

    for line in auth_lines:
        for pattern, severity, label in suspicious_patterns:
            if re.search(pattern, line):
                user_match = re.search(r"sudo\[\d+\]:\s+(\S+)\s*:", line)
                user = user_match.group(1) if user_match else "unknown"
                findings.append(Finding(
                    severity=severity,
                    category="Malicious Command",
                    title=f"{label} - user {user}",
                    description=(f"Detected execution pattern strongly associated with malicious activity. "
                                f"User: {user}. Pattern: {label}."),
                    evidence=[line.strip()],
                    recommendation=("Treat as active incident. Isolate the host immediately. "
                                   "Begin incident response: preserve evidence, identify scope, "
                                   "engage Legal under attorney-client privilege if data handling involved.")
                ))
                break
    return findings


def detect_port_scan(access_lines):
    """Detect port scanning behaviour."""
    findings = []
    scans = defaultdict(set)
    scan_lines = defaultdict(list)

    for line in access_lines:
        match = re.search(r"src=([\d.]+)\s+dst=([\d.]+)\s+dport=(\d+).*reason=no_rule", line)
        if match:
            src, dst, port = match.group(1), match.group(2), int(match.group(3))
            key = f"{src}->{dst}"
            scans[key].add(port)
            scan_lines[key].append(line.strip())

    for key, ports in scans.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            src, dst = key.split("->")
            ip_context = KNOWN_BAD_IPS.get(src, "")
            desc = f"Source {src} attempted connections to {len(ports)} different ports on {dst}: " + ", ".join(str(p) for p in sorted(ports)[:15])
            if len(ports) > 15:
                desc += f" (and {len(ports)-15} more)"
            if ip_context:
                desc += f". Source IP context: {ip_context}."

            findings.append(Finding(
                severity="High",
                category="Reconnaissance",
                title=f"Port scan from {src} targeting {dst}",
                description=desc,
                evidence=scan_lines[key][:3] + [f"... {len(scan_lines[key])-3} more blocked attempts"],
                recommendation=("Block source IP at perimeter. Review what ports/services are actually "
                               "exposed on the target. Consider whether external surface area should be reduced.")
            ))
    return findings


def detect_data_exfiltration(access_lines):
    """Detect large outbound data transfers."""
    findings = []
    for line in access_lines:
        match = re.search(r"src=([\d.]+)\s+dst=([\d.]+).*bytes_out=(\d+)", line)
        if match:
            src, dst, bytes_out = match.group(1), match.group(2), int(match.group(3))
            if bytes_out >= LARGE_TRANSFER_BYTES:
                gb = bytes_out / 1_000_000_000
                ip_context = KNOWN_BAD_IPS.get(dst, "")
                desc = f"Detected {gb:.2f} GB outbound transfer from internal host {src} to external IP {dst}."
                if ip_context:
                    desc += f" Destination IP context: {ip_context}."

                findings.append(Finding(
                    severity="Critical",
                    category="Data Exfiltration",
                    title=f"Large outbound transfer: {gb:.2f} GB to {dst}",
                    description=desc,
                    evidence=[line.strip()],
                    recommendation=("Treat as potential data breach. Block destination IP immediately. "
                                   "Identify what data was on the source host. Engage Legal and Privacy "
                                   "teams for breach assessment. Consider regulatory notification timelines: "
                                   "GDPR (72 hrs), NYDFS (72 hrs), DORA classification.")
                )) 
    return findings


def detect_crypto_mining(access_lines):
    """Detect connections to known crypto mining pools."""
    findings = []
    for line in access_lines:
        line_lower = line.lower()
        if any(indicator in line_lower for indicator in CRYPTO_MINING_INDICATORS):
            match = re.search(r"src=([\d.]+)\s+dst=([\d.]+)", line)
            if match:
                src, dst = match.group(1), match.group(2)
                findings.append(Finding(
                    severity="High",
                    category="Crypto Mining",
                    title=f"Crypto mining pool connection: {src} -> {dst}",
                    description=(f"Internal host {src} connected to a known crypto mining pool. "
                                f"This indicates either compromise (cryptojacking) or unauthorised use of "
                                f"company resources."),
                    evidence=[line.strip()],
                    recommendation=("Isolate the host. Investigate root cause: malware, compromised "
                                   "credentials, or insider activity. Review cloud cost anomalies. "
                                   "This pattern is consistent with cloud crypto mining incidents.")
                ))
    return findings


def detect_beaconing(access_lines):
    """Detect beaconing patterns - regular small connections to same destination."""
    findings = []
    connections = defaultdict(list)

    for line in access_lines:
        match = re.search(r"src=([\d.]+)\s+dst=([\d.]+).*bytes_out=(\d+)", line)
        if match:
            ts = parse_log_timestamp(line)
            if not ts:
                continue
            src, dst, bytes_out = match.group(1), match.group(2), int(match.group(3))
            connections[(src, dst)].append((ts, bytes_out, line.strip()))

    for (src, dst), conns in connections.items():
        if len(conns) >= 10:
            # Are they regularly spaced?
            conns.sort()
            intervals = [(conns[i+1][0] - conns[i][0]).total_seconds() for i in range(len(conns)-1)]
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                # Check regularity - are intervals consistent?
                consistent = sum(1 for i in intervals if abs(i - avg_interval) < avg_interval * 0.2)
                if consistent / len(intervals) > 0.7 and 30 <= avg_interval <= 600:
                    ip_context = KNOWN_BAD_IPS.get(dst, "")
                    desc = (f"Internal host {src} made {len(conns)} regularly-spaced connections to {dst} "
                           f"approximately every {int(avg_interval)} seconds. This pattern is consistent "
                           f"with malware command-and-control beaconing.")
                    if ip_context:
                        desc += f" Destination context: {ip_context}."

                    findings.append(Finding(
                        severity="Critical",
                        category="C2 Communication",
                        title=f"Beaconing pattern: {src} -> {dst}",
                        description=desc,
                        evidence=[c[2] for c in conns[:3]] + [f"... {len(conns)-3} more connections at ~{int(avg_interval)}s intervals"],
                        recommendation=("Treat as confirmed compromise. Isolate host from network. "
                                       "Begin full incident response. Investigate persistence mechanisms, "
                                       "lateral movement, and data access. Preserve volatile evidence.")
                    ))
    return findings


# === MAIN ANALYSIS ===

def analyse():
    print("Security Log Analyser Agent")
    print("=" * 60)

    # Read logs
    auth_log = LOG_DIR / "auth.log"
    access_log = LOG_DIR / "access.log"

    if not auth_log.exists() or not access_log.exists():
        print(f"ERROR: Log files not found in {LOG_DIR}")
        return

    with open(auth_log) as f:
        auth_lines = f.readlines()
    with open(access_log) as f:
        access_lines = f.readlines()

    print(f"Loaded {len(auth_lines)} auth events and {len(access_lines)} access events.")
    print("Running detection rules...\n")

    findings = []
    detections = [
        ("Brute force attacks", detect_brute_force, auth_lines),
        ("Successful brute force", detect_brute_force_success, auth_lines),
        ("Suspicious commands", detect_suspicious_commands, auth_lines),
        ("After-hours admin activity", detect_after_hours_admin, auth_lines),
        ("Port scans", detect_port_scan, access_lines),
        ("Data exfiltration", detect_data_exfiltration, access_lines),
        ("Crypto mining", detect_crypto_mining, access_lines),
        ("C2 beaconing", detect_beaconing, access_lines),
    ]

    for name, fn, data in detections:
        results = fn(data)
        print(f"  {name}: {len(results)} finding(s)")
        findings.extend(results)

    # Sort by severity
    findings.sort(key=lambda f: -f.severity_score())

    print(f"\nTotal findings: {len(findings)}")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            print(f"  {sev}: {count}")

    # Generate report
    generate_html_report(findings, len(auth_lines), len(access_lines))
    generate_json_report(findings)

    print(f"\nReport generated: {REPORT_DIR / 'risk_report.html'}")
    print(f"JSON output:      {REPORT_DIR / 'risk_report.json'}")
    print("\nOpen the HTML report in your browser to review findings.")


def generate_html_report(findings, auth_count, access_count):
    severity_colors = {
        "Critical": "#c0392b",
        "High": "#e67e22",
        "Medium": "#f39c12",
        "Low": "#27ae60"
    }
    severity_bg = {
        "Critical": "#fdedeb",
        "High": "#fdf2e9",
        "Medium": "#fef5e7",
        "Low": "#eafaf1"
    }

    counts = Counter(f.severity for f in findings)

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Risk Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          max-width: 1100px; margin: 40px auto; padding: 20px;
          background: #f5f7fa; color: #2c3e50; }}
  h1 {{ color: #1a2533; border-bottom: 3px solid #2e75b6; padding-bottom: 10px; }}
  h2 {{ color: #1f4e79; margin-top: 40px; }}
  .summary {{ background: white; padding: 25px; border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 30px; }}
  .stats {{ display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px; }}
  .stat-card {{ flex: 1; min-width: 150px; padding: 20px; border-radius: 6px;
                text-align: center; }}
  .stat-num {{ font-size: 36px; font-weight: bold; }}
  .stat-label {{ font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }}
  .finding {{ background: white; border-radius: 8px; padding: 25px;
              margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,0.05);
              border-left: 6px solid; }}
  .finding-header {{ display: flex; justify-content: space-between;
                     align-items: center; margin-bottom: 15px; }}
  .severity-badge {{ display: inline-block; padding: 4px 12px;
                     border-radius: 4px; color: white; font-weight: bold;
                     font-size: 12px; text-transform: uppercase; }}
  .category {{ color: #7f8c8d; font-size: 13px; text-transform: uppercase;
               letter-spacing: 1px; }}
  .finding-title {{ font-size: 18px; font-weight: bold; margin: 8px 0; color: #1a2533; }}
  .description {{ margin: 12px 0; line-height: 1.6; }}
  .evidence {{ background: #1a2533; color: #ecf0f1; padding: 12px;
               border-radius: 4px; font-family: 'SF Mono', Menlo, monospace;
               font-size: 12px; margin: 12px 0; overflow-x: auto;
               white-space: pre-wrap; word-break: break-all; }}
  .recommendation {{ background: #eaf6fc; padding: 15px; border-radius: 4px;
                     border-left: 4px solid #2e75b6; margin-top: 12px; }}
  .recommendation strong {{ color: #1f4e79; }}
  .meta {{ color: #95a5a6; font-size: 12px; margin-top: 30px; text-align: center; }}
</style>
</head>
<body>
<h1>Security Risk Report</h1>
<div class="summary">
  <p><strong>Generated:</strong> {datetime.now().strftime('%A, %B %d, %Y at %H:%M')}</p>
  <p><strong>Logs analysed:</strong> {auth_count} authentication events, {access_count} network events</p>
  <p><strong>Total findings:</strong> {len(findings)}</p>
  <div class="stats">"""

    for sev in ["Critical", "High", "Medium", "Low"]:
        count = counts.get(sev, 0)
        html += f"""
    <div class="stat-card" style="background: {severity_bg[sev]};">
      <div class="stat-num" style="color: {severity_colors[sev]};">{count}</div>
      <div class="stat-label" style="color: {severity_colors[sev]};">{sev}</div>
    </div>"""

    html += """
  </div>
</div>
<h2>Findings</h2>
"""

    if not findings:
        html += "<p>No security issues detected. All clear.</p>"
    else:
        for i, f in enumerate(findings, 1):
            evidence_html = "\n".join(f.evidence)
            html += f"""
<div class="finding" style="border-left-color: {severity_colors[f.severity]};">
  <div class="finding-header">
    <div>
      <span class="severity-badge" style="background: {severity_colors[f.severity]};">{f.severity}</span>
      <span class="category" style="margin-left: 10px;">{f.category}</span>
    </div>
    <span style="color: #95a5a6; font-size: 12px;">Finding #{i}</span>
  </div>
  <div class="finding-title">{f.title}</div>
  <div class="description">{f.description}</div>
  <div><strong>Evidence:</strong></div>
  <div class="evidence">{evidence_html}</div>
  <div class="recommendation"><strong>Recommended Action:</strong> {f.recommendation}</div>
</div>
"""

    html += f"""
<div class="meta">
  Security Log Analyser Agent | Generated locally on your machine | No data transmitted externally
</div>
</body>
</html>
"""

    with open(REPORT_DIR / "risk_report.html", "w") as out:
        out.write(html)


def generate_json_report(findings):
    data = {
        "generated": datetime.now().isoformat(),
        "total_findings": len(findings),
        "summary": dict(Counter(f.severity for f in findings)),
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation
            } for f in findings
        ]
    }
    with open(REPORT_DIR / "risk_report.json", "w") as out:
        json.dump(data, out, indent=2)


if __name__ == "__main__":
    analyse()
