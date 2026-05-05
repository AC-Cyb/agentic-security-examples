# Detection Agent

A security log analyser that reads log files, identifies anomalous patterns,
scores findings by severity, and generates an HTML risk report.

## What It Detects

| Category | Severity Range | Detection Approach |
|---|---|---|
| Brute force attacks | High → Critical | Threshold of failed logins from same source within time window |
| Successful brute force (compromise) | Critical | Successful login from IP that just had many failures |
| Suspicious commands | Medium → Critical | Pattern match on known malicious command signatures |
| After-hours admin activity | Medium | Sudo/root activity outside business hours |
| Port scans | High | Many distinct ports targeted from a single source |
| Data exfiltration | Critical | Large outbound transfers from internal hosts |
| Crypto mining | High | Connections to known mining pool indicators |
| C2 beaconing | Critical | Regularly-spaced connections to suspicious destinations |

## Architecture

```
Detection Agent
├── Input:        Log files (auth.log, access.log)
├── Processing:   Eight parallel detection rules
├── Scoring:      Severity tiering (Critical / High / Medium / Low)
├── Enrichment:   Known-bad IP context, regulatory framework references
└── Output:       HTML report + JSON for downstream tooling
```

## Setup

No dependencies beyond Python 3.8+. Just run:

```bash
cd 01-detection-agent
python3 analyser.py
open reports/risk_report.html
```

## Files

- `analyser.py` — main detection engine
- `generate_auth.py` — synthetic auth log generator (regenerate with realistic events)
- `generate_access.py` — synthetic network access log generator
- `logs/` — sample log files (regenerate with `python3 generate_auth.py && python3 generate_access.py`)
- `reports/` — output reports (HTML and JSON)

## Using With Your Own Logs

Drop real log files into `logs/` and run the analyser. The detection rules currently
expect syslog-style format. To adapt to other formats (CloudTrail JSON, Windows Event Log XML, etc.),
modify the parsing functions in `analyser.py` — the detection logic itself is format-agnostic.

## Production Considerations

This agent is a reference implementation. For production use:

- **Streaming input** — replace file reads with a streaming connector (Kafka, Kinesis, syslog receiver)
- **Distributed processing** — partition by log source to scale horizontally
- **State management** — track detected events to avoid duplicate alerts on overlapping log windows
- **Threshold tuning** — current thresholds are conservative defaults; tune to your environment baseline
- **Threat intelligence feeds** — replace the static known-bad IP list with live feeds (MISP, AbuseIPDB)
