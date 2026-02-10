def infer_severity(event: dict) -> str:
    event_type = event.get("event_type")

    if event_type in {"ssh_failed_login", "ssh_invalid_user"}:
        return "medium"
    if event_type == "ssh_success_login":
        return "low"

    return "info"
