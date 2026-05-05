import random
from datetime import datetime, timedelta

random.seed(43)

start = datetime.now() - timedelta(days=7)
lines = []

normal_destinations = [
    ("172.217.16.46", 443, "google.com"),
    ("31.13.65.36", 443, "facebook.com"),
    ("13.226.45.78", 443, "aws.amazon.com"),
    ("140.82.121.4", 443, "github.com"),
    ("104.244.42.65", 443, "twitter.com"),
    ("199.232.69.194", 443, "stackoverflow.com"),
    ("162.255.119.84", 443, "slack.com"),
    ("13.107.42.14", 443, "office.com"),
]

internal_ips = [f"10.0.{random.randint(1,5)}.{random.randint(10,250)}" for _ in range(15)]

def fmt_time(dt):
    return dt.strftime("%b %d %H:%M:%S")

# Normal traffic - 7 days
for day_offset in range(7):
    day_start = start + timedelta(days=day_offset)
    for _ in range(random.randint(15, 25)):
        ts = day_start + timedelta(hours=random.randint(7, 22), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        src = random.choice(internal_ips)
        dst_ip, dst_port, dst_host = random.choice(normal_destinations)
        bytes_out = random.randint(500, 50000)
        bytes_in = random.randint(2000, 500000)
        lines.append((ts, f"{fmt_time(ts)} firewall: ALLOW src={src} dst={dst_ip} dport={dst_port} proto=tcp host={dst_host} bytes_out={bytes_out} bytes_in={bytes_in}"))

# === SUSPICIOUS EVENTS ===

# Event 1: Port scan from external IP - sequential ports across short time
scan_day = start + timedelta(days=3)
scanner_ip = "91.243.59.27"
target_ip = "10.0.1.45"
for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]):
    ts = scan_day + timedelta(hours=4, minutes=23, seconds=i*2)
    lines.append((ts, f"{fmt_time(ts)} firewall: BLOCK src={scanner_ip} dst={target_ip} dport={port} proto=tcp reason=no_rule"))

# Event 2: Beaconing pattern - regular outbound connections to suspicious IP
beacon_day = start + timedelta(days=6)
beacon_ip = "194.165.16.118"
beacon_src = "10.0.2.137"  # The infected machine from auth.log
for i in range(15):
    ts = beacon_day + timedelta(hours=23, minutes=50, seconds=i*60)  # Every 60 seconds
    lines.append((ts, f"{fmt_time(ts)} firewall: ALLOW src={beacon_src} dst={beacon_ip} dport=443 proto=tcp bytes_out=412 bytes_in=128"))

# Event 3: Large data exfiltration
exfil_day = start + timedelta(days=5)
ts = exfil_day + timedelta(hours=2, minutes=45)
lines.append((ts, f"{fmt_time(ts)} firewall: ALLOW src=10.0.1.45 dst=185.220.101.45 dport=443 proto=tcp bytes_out=4823651200 bytes_in=2048"))

# Event 4: Connection to known crypto mining pool
crypto_day = start + timedelta(days=4)
ts = crypto_day + timedelta(hours=14, minutes=22)
lines.append((ts, f"{fmt_time(ts)} firewall: ALLOW src=10.0.3.89 dst=51.91.124.36 dport=3333 proto=tcp host=xmr-pool.minexmr.com bytes_out=125000 bytes_in=87000"))
ts2 = ts + timedelta(minutes=15)
lines.append((ts2, f"{fmt_time(ts2)} firewall: ALLOW src=10.0.3.89 dst=51.91.124.36 dport=3333 proto=tcp host=xmr-pool.minexmr.com bytes_out=215000 bytes_in=156000"))

lines.sort(key=lambda x: x[0])

with open("/home/claude/security_project/logs/access.log", "w") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"Generated {len(lines)} access.log entries")
