"""
Generate realistic log files with embedded secrets and PII for testing.
These are FAKE credentials - they won't authenticate to anything real.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

start = datetime.now() - timedelta(days=2)


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# ============== application.log ==============
# Realistic backend application log with secrets/PII bleeding into logs
app_lines = []

ts = start
for i in range(80):
    ts += timedelta(minutes=random.randint(1, 15))
    events = [
        f"{fmt(ts)} INFO  [request-handler] Processing request from user {random.choice(['alice', 'bob', 'charlie', 'diana'])}",
        f"{fmt(ts)} DEBUG [db-pool] Connection acquired (active=12, idle=8)",
        f"{fmt(ts)} INFO  [auth-service] Token validated for user_id={random.randint(1000, 9999)}",
        f"{fmt(ts)} INFO  [api] GET /api/v1/users/profile returned 200",
        f"{fmt(ts)} DEBUG [cache] Cache hit ratio: 0.87",
    ]
    app_lines.append(random.choice(events))

# Inject realistic security incidents - secrets/PII in logs
incident_lines = [
    # AWS keys exposed
    f"{fmt(start + timedelta(hours=4))} ERROR [aws-client] Failed to connect: aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    f"{fmt(start + timedelta(hours=4, minutes=2))} INFO  [config] Loaded credentials: AKIA1A2B3C4D5E6F7G8H",

    # Database URL with embedded password
    f"{fmt(start + timedelta(hours=5))} INFO  [db-init] Connecting to postgres://admin:[email protected]:5432/production",
    f"{fmt(start + timedelta(hours=5, minutes=3))} ERROR [db-conn] Connection refused: postgresql://dbuser:[email protected]/userdb",

    # API tokens in logs
    f"{fmt(start + timedelta(hours=6))} DEBUG [http] Request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    f"{fmt(start + timedelta(hours=6, minutes=15))} INFO  [github-sync] Using token ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR for repo sync",
    f"{fmt(start + timedelta(hours=6, minutes=20))} INFO  [slack] Posting alert via xoxb-1234567890-abcdefghijklmnop",

    # Stripe keys
    f"{fmt(start + timedelta(hours=7))} ERROR [payment] Charge failed for stripe key sk_live_51HJxYzKjLmNoPqRsTuVwXyZaBcDeFgHi",

    # Customer data leak
    f"{fmt(start + timedelta(hours=8))} INFO  [order-service] Order created for [email protected], phone 408-555-1234, card 4532-1488-0343-6467",
    f"{fmt(start + timedelta(hours=8, minutes=10))} ERROR [validation] Failed validation for user: ssn=123-45-6789, dob=1985-03-15",

    # Customer ID
    f"{fmt(start + timedelta(hours=9))} INFO  [billing] Invoice generated for CUST-A8B9C0D1E2 amount=$1,247.50",

    # Employee ID with PII
    f"{fmt(start + timedelta(hours=10))} WARN  [hr-sync] Sync failed for EMP-487293 ([email protected])",

    # Password in plaintext
    f"{fmt(start + timedelta(hours=11))} DEBUG [test-fixtures] Loaded test user with password=SuperSecret123!",
    f"{fmt(start + timedelta(hours=11, minutes=30))} INFO  [auth] Failed login - password='admin123' rejected",

    # Generic API key
    f"{fmt(start + timedelta(hours=12))} INFO  [external-api] Calling vendor with api_key: 9f8e7d6c5b4a3210fedcba9876543210",

    # IBAN
    f"{fmt(start + timedelta(hours=13))} INFO  [transfer] Wire transfer to GB29NWBK60161331926819 completed",

    # IP addresses (mixed - some should be flagged, others internal)
    f"{fmt(start + timedelta(hours=14))} INFO  [firewall] Connection from 203.0.113.45 to internal 10.0.1.50",
]

app_lines.extend(incident_lines)

# More noise
ts = start + timedelta(hours=15)
for i in range(40):
    ts += timedelta(minutes=random.randint(1, 10))
    app_lines.append(f"{fmt(ts)} INFO  [health-check] Status OK, uptime={random.randint(1000, 99999)}s")

with open(LOG_DIR / "application.log", "w") as f:
    f.write("\n".join(app_lines))


# ============== access.log (web server style) ==============
access_lines = []

# Normal access
ts = start
for i in range(60):
    ts += timedelta(seconds=random.randint(10, 300))
    ip = f"203.0.113.{random.randint(1, 254)}"
    user = random.choice(["-", "alice", "bob"])
    access_lines.append(f'{ip} - {user} [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/v1/products HTTP/1.1" 200 1543')

# Problematic - URL params with secrets/PII
problematic = [
    f'203.0.113.42 - - [{(start + timedelta(hours=2)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/login?username=admin&password=Hunter2!password HTTP/1.1" 200 245',
    f'203.0.113.42 - - [{(start + timedelta(hours=2, minutes=5)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/data?api_key=sk_test_abc123def456ghi789jkl012mno345pqr&id=42 HTTP/1.1" 200 1024',
    f'203.0.113.99 - [email protected] [{(start + timedelta(hours=3)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/payment HTTP/1.1" 201 512',
    f'45.142.214.89 - - [{(start + timedelta(hours=4)).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /admin?token=eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature_part_here_xyzabc HTTP/1.1" 403 87',
]

access_lines.extend(problematic)

with open(LOG_DIR / "access.log", "w") as f:
    f.write("\n".join(access_lines))


# ============== debug.log (development log with disasters) ==============
debug_lines = [
    "# Debug log generated during testing - SHOULD NEVER REACH PRODUCTION",
    "",
    "[DEBUG] Initialising connection pool...",
    "[DEBUG] Loaded config from environment:",
    "[DEBUG]   AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEYIDXXXX",
    "[DEBUG]   AWS_SECRET_ACCESS_KEY=ExAmPlE/SeCrEtKeY+WiTh40CharsHerePqRsTu",
    "[DEBUG]   DATABASE_URL=postgresql://app_user:[email protected]:5432/app_prod",
    "[DEBUG]   STRIPE_KEY=sk_live_FAKEexampleStripeKeyForTestingOnly",
    "[DEBUG]   GITHUB_TOKEN=ghp_FAKEtokenExampleForTestingPurposes12",
    "",
    "[DEBUG] Loading test fixtures...",
    "[DEBUG]   Test user 1: email=[email protected], ssn=987-65-4321, card=5425-2334-3010-9903",
    "[DEBUG]   Test user 2: email=[email protected], ssn=234-56-7890, card=4532-1488-0343-6467",
    "[DEBUG]   Test user 3: passport_no=A12345678 employee_id=EMP-100234",
    "",
    "[DEBUG] Private key loaded:",
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEpAIBAAKCAQEAyZ7Q5UeHvVN8kF3qXr8mLpRtY5wSdEf2iUjBhKcVnAxGsHMtNvP",
    "[... key content truncated for brevity ...]",
    "-----END RSA PRIVATE KEY-----",
    "",
    "[DEBUG] Customer records imported:",
    "[DEBUG]   CUST-X1Y2Z3A4B5: [email protected], +1-555-867-5309",
    "[DEBUG]   CUST-M9N8O7P6Q5: [email protected], 415.555.0123",
]

with open(LOG_DIR / "debug.log", "w") as f:
    f.write("\n".join(debug_lines))


print(f"Generated 3 log files in {LOG_DIR}/")
print(f"  application.log: {sum(1 for _ in open(LOG_DIR / 'application.log'))} lines")
print(f"  access.log:      {sum(1 for _ in open(LOG_DIR / 'access.log'))} lines")
print(f"  debug.log:       {sum(1 for _ in open(LOG_DIR / 'debug.log'))} lines")
