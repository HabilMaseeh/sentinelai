import re
from datetime import datetime, timezone

PATTERNS = [
    {
        "regex": re.compile(
            r"Failed password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "ssh_failed_login"
    },
    {
        "regex": re.compile(
            r"Invalid user (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "ssh_invalid_user"
    },
    {
        "regex": re.compile(
            r"Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        ),
        "event_type": "ssh_success_login"
    }
]

def parse_auth_log(line: str):
    for pattern in PATTERNS:
        match = pattern["regex"].search(line)
        if match:
            return {
                "event_time": datetime.now(timezone.utc), 
                "source": "linux_auth",
                "event_type": pattern["event_type"],
                "username": match.group("user"),
                "ip_address": match.group("ip"),
                "message": line.strip()
            }
    return None

