"""
Sample authentication tokens for testing the multi-agent system.

Each token comes with metadata about the request context (IP, user agent,
timestamp, etc) and the actual token data. The agents will analyze these
from different angles and the coordinator will synthesize a decision.

In production these would arrive as real authentication requests at an
API gateway or web app. Here they are pre-built scenarios that exercise
the different detection paths.
"""

from datetime import datetime, timedelta

# Reference time - a recent timestamp for "now" in the scenarios
NOW = datetime.now()


def _ts(minutes_ago=0):
    return (NOW - timedelta(minutes=minutes_ago)).isoformat()


SAMPLE_REQUESTS = [
    # ============== TOKEN-001: Clean valid request ==============
    {
        "request_id": "REQ-001",
        "scenario_name": "Valid user, normal context",
        "expected_disposition": "allow",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEwMDQiLCJpc3MiOiJhdXRoLmZpbnRlY2guY29tIiwiYXVkIjoiYXBpLmZpbnRlY2guY29tIiwiZXhwIjoxNzMyMDAwMDAwLCJpYXQiOjE3MzE5OTY0MDAsInJvbGVzIjpbInVzZXIiXSwic2Vzc2lvbl9pZCI6InNlc3NfYWJjMTIzIn0.signature",
            "claims": {
                "sub": "user_1004",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 1800,
                "iat_minutes_ago": 5,
                "alg": "RS256",
                "roles": ["user"],
                "session_id": "sess_abc123",
            }
        },
        "context": {
            "source_ip": "203.0.113.45",
            "ip_reputation": "clean",
            "ip_geo": "Boston, US",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)",
            "request_path": "/api/v1/account/balance",
            "method": "GET",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1004",
            "typical_locations": ["Boston, US", "New York, US"],
            "typical_user_agents": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"],
            "last_login": _ts(120),
            "last_login_ip": "203.0.113.42",
        }
    },

    # ============== TOKEN-002: Expired token ==============
    {
        "request_id": "REQ-002",
        "scenario_name": "Expired token from legitimate user",
        "expected_disposition": "challenge",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwMDQiLCJleHAiOjE3MDAwMDAwMDB9.expired",
            "claims": {
                "sub": "user_1004",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": -300,  # expired 5 minutes ago
                "iat_minutes_ago": 65,
                "alg": "RS256",
                "roles": ["user"],
                "session_id": "sess_xyz789",
            }
        },
        "context": {
            "source_ip": "203.0.113.45",
            "ip_reputation": "clean",
            "ip_geo": "Boston, US",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)",
            "request_path": "/api/v1/account/transfer",
            "method": "POST",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1004",
            "typical_locations": ["Boston, US", "New York, US"],
            "typical_user_agents": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"],
            "last_login": _ts(120),
            "last_login_ip": "203.0.113.42",
        }
    },

    # ============== TOKEN-003: Algorithm confusion attack ==============
    {
        "request_id": "REQ-003",
        "scenario_name": "Algorithm confusion attack (alg=none)",
        "expected_disposition": "revoke",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl19.",
            "claims": {
                "sub": "admin",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 3600,
                "iat_minutes_ago": 1,
                "alg": "none",  # Critical: no algorithm
                "roles": ["admin"],
                "session_id": "sess_attacker",
            }
        },
        "context": {
            "source_ip": "185.220.101.45",
            "ip_reputation": "malicious",
            "ip_geo": "Tor exit node",
            "user_agent": "curl/7.81.0",
            "request_path": "/api/v1/admin/users",
            "method": "GET",
            "timestamp": _ts(0),
        },
        "user_history": None,
    },

    # ============== TOKEN-004: Token from impossible location ==============
    {
        "request_id": "REQ-004",
        "scenario_name": "Valid token but impossible travel detected",
        "expected_disposition": "challenge",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwMDQifQ.signature",
            "claims": {
                "sub": "user_1004",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 1700,
                "iat_minutes_ago": 8,
                "alg": "RS256",
                "roles": ["user"],
                "session_id": "sess_abc123",
            }
        },
        "context": {
            "source_ip": "194.165.16.118",
            "ip_reputation": "suspicious",
            "ip_geo": "Moscow, RU",  # impossible from Boston in 8 minutes
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "request_path": "/api/v1/account/transfer",
            "method": "POST",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1004",
            "typical_locations": ["Boston, US", "New York, US"],
            "typical_user_agents": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"],
            "last_login": _ts(8),  # 8 minutes ago from Boston
            "last_login_ip": "203.0.113.42",
        }
    },

    # ============== TOKEN-005: Replay attack ==============
    {
        "request_id": "REQ-005",
        "scenario_name": "Token replay attack - same JTI seen multiple times",
        "expected_disposition": "revoke",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJ0a25fcmVwbGF5In0.signature",
            "claims": {
                "sub": "user_1009",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 900,
                "iat_minutes_ago": 25,
                "alg": "RS256",
                "roles": ["user"],
                "session_id": "sess_replay",
                "jti": "tkn_replay",  # this token has been seen before
            }
        },
        "context": {
            "source_ip": "45.142.214.89",
            "ip_reputation": "malicious",
            "ip_geo": "Unknown",
            "user_agent": "python-requests/2.31.0",  # automation tool
            "request_path": "/api/v1/payments/initiate",
            "method": "POST",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1009",
            "typical_locations": ["San Francisco, US"],
            "typical_user_agents": ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"],
            "last_login": _ts(45),
            "last_login_ip": "192.0.2.50",
        }
    },

    # ============== TOKEN-006: Privilege escalation in claims ==============
    {
        "request_id": "REQ-006",
        "scenario_name": "Suspicious privilege escalation - non-admin user with admin claims",
        "expected_disposition": "revoke",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwMDcifQ.tampered_signature",
            "claims": {
                "sub": "user_1007",  # known non-admin user
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 3600,
                "iat_minutes_ago": 2,
                "alg": "RS256",
                "roles": ["admin", "superuser"],  # suspicious - this user shouldn't have these
                "session_id": "sess_escalate",
            }
        },
        "context": {
            "source_ip": "10.0.5.23",
            "ip_reputation": "internal",
            "ip_geo": "Internal network",
            "user_agent": "PostmanRuntime/7.36.0",
            "request_path": "/api/v1/admin/policies",
            "method": "PUT",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1007",
            "typical_locations": ["Internal network"],
            "typical_user_agents": ["Mozilla/5.0 (Windows NT 10.0)"],
            "last_login": _ts(180),
            "last_login_ip": "10.0.5.23",
            "expected_roles": ["user"],  # user_1007 should only have 'user' role
        }
    },

    # ============== TOKEN-007: API key from automated agent ==============
    {
        "request_id": "REQ-007",
        "scenario_name": "Service account API key - legitimate automation",
        "expected_disposition": "allow",
        "token": {
            "type": "api_key",
            "value": "sk_live_serviceacct_abc123def456",
            "claims": {
                "sub": "svc_payment_processor",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": None,  # API keys typically don't expire
                "iat_minutes_ago": None,
                "alg": None,
                "roles": ["service:payment_processor"],
                "session_id": None,
            }
        },
        "context": {
            "source_ip": "10.0.10.42",
            "ip_reputation": "internal",
            "ip_geo": "Internal network",
            "user_agent": "fintech-payment-service/2.4.1",
            "request_path": "/api/v1/payments/process",
            "method": "POST",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "svc_payment_processor",
            "typical_locations": ["Internal network"],
            "typical_user_agents": ["fintech-payment-service/2.4.1"],
            "last_login": _ts(2),
            "last_login_ip": "10.0.10.42",
        }
    },

    # ============== TOKEN-008: Anomalous user agent ==============
    {
        "request_id": "REQ-008",
        "scenario_name": "Valid token but anomalous user agent",
        "expected_disposition": "challenge",
        "token": {
            "type": "jwt",
            "value": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEwMTIifQ.signature",
            "claims": {
                "sub": "user_1012",
                "iss": "auth.fintech.com",
                "aud": "api.fintech.com",
                "exp_in_seconds": 1500,
                "iat_minutes_ago": 10,
                "alg": "RS256",
                "roles": ["user"],
                "session_id": "sess_user1012",
            }
        },
        "context": {
            "source_ip": "203.0.113.99",
            "ip_reputation": "clean",
            "ip_geo": "San Francisco, US",
            "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",  # bot user agent
            "request_path": "/api/v1/account/profile",
            "method": "GET",
            "timestamp": _ts(0),
        },
        "user_history": {
            "user_id": "user_1012",
            "typical_locations": ["San Francisco, US"],
            "typical_user_agents": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"],
            "last_login": _ts(60),
            "last_login_ip": "203.0.113.95",
        }
    },
]
