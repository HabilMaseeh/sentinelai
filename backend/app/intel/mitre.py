MITRE_MAP = {
    "Brute Force Attack": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "Credential Enumeration": {
        "technique": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery"
    }
}

def get_mitre(incident):
    return MITRE_MAP.get(incident, None)
