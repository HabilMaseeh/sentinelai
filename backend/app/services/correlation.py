from collections import defaultdict
from datetime import datetime, timedelta, timezone

class CorrelationEngine:
    def __init__(self):
        self.activity = defaultdict(list)

    def add_event(self, event):
        ip = event["ip_address"]
        self.activity[ip].append({
            "type": event["event_type"],
            "time": datetime.now(timezone.utc)
        })

    def evaluate(self, ip):
        now = datetime.now(timezone.utc)
        recent = [
            e for e in self.activity[ip]
            if now - e["time"] < timedelta(minutes=2)
        ]

        types = [e["type"] for e in recent]

        # Correlation rules (simple but realistic)
        failed_count = types.count("ssh_failed_login")
        invalid_count = types.count("ssh_invalid_user")

        if failed_count >= 5:
            return {
                "incident": "Brute Force Attack",
                "confidence": "high",
                "count": failed_count
            }

        if invalid_count > 0 and failed_count > 0:
            return {
                "incident": "Credential Enumeration",
                "confidence": "medium",
                "count": invalid_count + failed_count
            }

        return None


correlator = CorrelationEngine()
