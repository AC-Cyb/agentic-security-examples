"""
Sample authentication incidents - in production these would come from your SIEM,
detection agent (like Project 1), or threat intelligence feeds.
"""

SAMPLE_FINDINGS = [
    {
        "id": "FIND-001",
        "type": "brute_force_success",
        "severity": "Critical",
        "title": "Successful login after brute force attack",
        "description": "User jsmith authenticated successfully from 185.220.101.45 (Tor exit node) following 47 failed attempts within the previous hour. Strong indicator of credential compromise.",
        "username": "jsmith",
        "source_ip": "185.220.101.45",
        "ip_reputation": "malicious",
        "ip_context": "Tor exit node - frequently associated with attacks",
        "session_id": "sess_d4e5f6",
        "evidence": [
            "47 failed SSH attempts from 185.220.101.45 between 02:15 and 02:21",
            "Successful authentication for jsmith at 02:21:30",
            "Source IP geolocates to Russia (user is based in Boston)",
        ]
    },
    {
        "id": "FIND-002",
        "type": "impossible_travel",
        "severity": "High",
        "title": "Impossible travel detected for user kchen",
        "description": "User kchen has two active sessions: one from internal network (10.0.2.137) and one from 194.165.16.118 (known C2 infrastructure). Geographic and behavioural impossibility.",
        "username": "kchen",
        "source_ip": "194.165.16.118",
        "ip_reputation": "malicious",
        "ip_context": "Malware delivery infrastructure - associated with recent campaigns",
        "session_id": "sess_j0k1l2",
        "evidence": [
            "Active session from 10.0.2.137 (corporate network) since 5 hours ago",
            "New session from 194.165.16.118 started 30 minutes ago",
            "Destination IP flagged in threat intel as C2 infrastructure",
        ]
    },
    {
        "id": "FIND-003",
        "type": "anomalous_login_location",
        "severity": "Medium",
        "title": "Login from unusual country for rgarcia",
        "description": "User rgarcia authenticated from an IP that geolocates to a country they have not previously logged in from.",
        "username": "rgarcia",
        "source_ip": "203.0.113.42",
        "ip_reputation": "unknown",
        "ip_context": "No threat intelligence match - novel location",
        "session_id": "sess_m3n4o5",
        "evidence": [
            "First-time login from this geographic region",
            "Login during user's typical work hours",
            "MFA was completed successfully",
        ]
    },
    {
        "id": "FIND-004",
        "type": "stale_password_low_risk_alert",
        "severity": "Low",
        "title": "Service account password is stale",
        "description": "Service account admin_svc has not had its password rotated in over 8 months. Best practice rotation interval is 90 days.",
        "username": "admin_svc",
        "source_ip": "10.0.0.12",
        "ip_reputation": "trusted",
        "ip_context": "Internal infrastructure",
        "session_id": None,
        "evidence": [
            "Last password change: 2025-08-01",
            "Days since rotation: 268",
            "Account is privileged (admin role)",
        ]
    },
]
