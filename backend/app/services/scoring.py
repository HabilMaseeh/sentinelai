def calculate_risk(incident_type, event_count):
    base = {
        "Brute Force Attack": 7,
        "Credential Enumeration": 5,
        "Privilege Escalation Attempt": 9
    }

    score = base.get(incident_type, 3)
    score += min(event_count // 3, 3)  # scale severity

    return min(score, 10)
