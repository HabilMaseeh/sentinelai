def recommend_actions(incident: str | None, counts: dict | None, enrichment: dict | None) -> list[str]:
    actions = []

    if incident and "Brute Force" in incident:
        actions.append("Block offending IP at firewall or security group.")
        actions.append("Enable account lockout after repeated failures.")
        actions.append("Enforce MFA on affected accounts.")

    if incident and "Credential Enumeration" in incident:
        actions.append("Rate-limit authentication attempts.")
        actions.append("Disable or rename default accounts.")
        actions.append("Enable login banner and monitoring.")

    if incident and "Multi-Source User Activity" in incident:
        actions.append("Verify user session legitimacy across IPs.")
        actions.append("Force password reset for the affected user.")
        actions.append("Review VPN and geo-access policies.")

    if counts and counts.get("invalid", 0) > 0:
        actions.append("Harden SSH: disable password auth where possible.")

    if enrichment and enrichment.get("is_private") is False:
        actions.append("Check IP reputation with external threat intel.")

    return actions or ["Monitor activity and collect additional context."]
