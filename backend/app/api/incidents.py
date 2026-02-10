from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from fastapi import APIRouter, Query, Response

from app.core.database import ueba_incidents_collection, logs_collection
from app.services.remediation import recommend_actions
from app.services.threat_intel import lookup_ip

router = APIRouter()


@router.get("/incidents")
async def get_incidents(
    limit: int = Query(50, le=200)
):
    cursor = ueba_incidents_collection.find({}).sort("risk_score", -1).limit(limit)
    incidents = []

    async for inc in cursor:
        inc["_id"] = str(inc["_id"])

        last_seen = inc.get("last_seen") or inc.get("timestamp")
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if last_seen:
            minutes = (datetime.now(timezone.utc) - last_seen).total_seconds() / 60.0
            decayed = max(1.0, inc.get("risk_score", 5) - (minutes / 10.0))
            inc["risk_score_decayed"] = round(decayed, 2)

        incidents.append(inc)

    return incidents


@router.get("/incidents/{incident_key}/details")
async def get_incident_details(incident_key: str):
    incident = await ueba_incidents_collection.find_one({"incident_key": incident_key})
    if not incident:
        return {"error": "Incident not found"}

    incident["_id"] = str(incident["_id"])

    last_seen = incident.get("last_seen") or incident.get("timestamp")
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if not last_seen:
        return {"incident": incident, "timeline": [], "graph": {"nodes": [], "edges": []}}

    window_start = last_seen - timedelta(minutes=30)
    ip = incident.get("ip_address")

    cursor = logs_collection.find(
        {"ip_address": ip, "event_time": {"$gte": window_start}},
        {"event_time": 1, "event_type": 1, "username": 1, "ip_address": 1, "message": 1}
    ).sort("event_time", 1).limit(200)

    timeline = []
    users = set()
    counts = {"failed": 0, "invalid": 0, "success": 0, "total": 0}

    async for log in cursor:
        counts["total"] += 1
        if log.get("event_type") == "ssh_failed_login":
            counts["failed"] += 1
        elif log.get("event_type") == "ssh_invalid_user":
            counts["invalid"] += 1
        elif log.get("event_type") == "ssh_success_login":
            counts["success"] += 1

        if log.get("username"):
            users.add(log["username"])

        timeline.append({
            "time": log.get("event_time"),
            "event_type": log.get("event_type"),
            "username": log.get("username"),
            "ip_address": log.get("ip_address"),
            "message": log.get("message")
        })

    nodes = [{"id": ip, "type": "ip"}]
    edges = []
    for user in sorted(users):
        nodes.append({"id": user, "type": "user"})
        edges.append({"from": user, "to": ip, "type": "auth"})

    summary = (
        f"Window 30m: total={counts['total']}, failed={counts['failed']}, "
        f"invalid={counts['invalid']}, success={counts['success']}."
    )

    enrichment = {}
    if ip:
        addr = ip_address(ip)
        enrichment = {
            "ip": ip,
            "is_private": addr.is_private,
            "is_reserved": addr.is_reserved,
            "is_global": addr.is_global
        }

    threat_intel = {}
    if ip and enrichment.get("is_private") is False:
        threat_intel = await lookup_ip(ip)

    recommendations = recommend_actions(
        incident.get("incident"),
        counts,
        enrichment
    )

    return {
        "incident": incident,
        "summary": summary,
        "counts": counts,
        "timeline": timeline,
        "graph": {"nodes": nodes, "edges": edges},
        "enrichment": enrichment,
        "threat_intel": threat_intel,
        "recommendations": recommendations,
        "kill_chain_stage": incident.get("kill_chain_stage"),
        "kill_chain_all": [
            "Reconnaissance",
            "Discovery",
            "Credential Access",
            "Lateral Movement",
            "Exfiltration",
            "Impact"
        ]
    }


@router.get("/incidents/{incident_key}/report")
async def get_incident_report(incident_key: str, format: str = "txt"):
    incident = await ueba_incidents_collection.find_one({"incident_key": incident_key})
    if not incident:
        return Response("Incident not found", media_type="text/plain", status_code=404)

    last_seen = incident.get("last_seen") or incident.get("timestamp")
    if last_seen and last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    lines = [
        "SentinelAI Incident Report",
        f"Incident Key: {incident_key}",
        f"Incident: {incident.get('incident', '-')}",
        f"IP: {incident.get('ip_address', '-')}",
        f"Severity: {incident.get('severity', '-')}",
        f"Risk Score: {incident.get('risk_score', '-')}",
        f"Kill Chain: {incident.get('kill_chain_stage', '-')}",
        f"Last Seen (UTC): {last_seen.isoformat() if last_seen else '-'}",
        "",
        "Summary:",
        incident.get("description", "-")
    ]

    if format == "html":
        html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>SentinelAI Incident Report</title></head>
<body style="font-family: Arial, sans-serif;">
<h1>SentinelAI Incident Report</h1>
<p><strong>Incident Key:</strong> {incident_key}</p>
<p><strong>Incident:</strong> {incident.get('incident', '-')}</p>
<p><strong>IP:</strong> {incident.get('ip_address', '-')}</p>
<p><strong>Severity:</strong> {incident.get('severity', '-')}</p>
<p><strong>Risk Score:</strong> {incident.get('risk_score', '-')}</p>
<p><strong>Kill Chain:</strong> {incident.get('kill_chain_stage', '-')}</p>
<p><strong>Last Seen (UTC):</strong> {last_seen.isoformat() if last_seen else '-'}</p>
<h3>Summary</h3>
<p>{incident.get('description', '-')}</p>
</body>
</html>"""
        headers = {
            "Content-Disposition": f"attachment; filename=incident-{incident_key}.html"
        }
        return Response(html, media_type="text/html", headers=headers)

    headers = {
        "Content-Disposition": f"attachment; filename=incident-{incident_key}.txt"
    }
    return Response("\n".join(lines), media_type="text/plain", headers=headers)
