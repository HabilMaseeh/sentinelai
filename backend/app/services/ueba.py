from datetime import datetime, timedelta, timezone

from app.core.database import (
    logs_collection,
    ueba_profiles_collection,
    ueba_user_profiles_collection,
    ueba_sessions_collection,
    ueba_incidents_collection
)
from app.intel.mitre import get_mitre
from app.services.scoring import calculate_risk


WINDOW_MINUTES = 10
COOLDOWN_MINUTES = 5
SESSION_GAP_MINUTES = 5

FAILED_THRESHOLD = 8
INVALID_THRESHOLD = 3
BURST_THRESHOLD = 25

EMA_ALPHA = 0.2


KILL_CHAIN = {
    "UEBA: Persistent Brute Force": "Credential Access",
    "UEBA: Credential Enumeration": "Discovery",
    "UEBA: Abnormal Activity Burst": "Reconnaissance",
    "UEBA: Multi-Source User Activity": "Lateral Movement",
    "UEBA: Rare Entity Observed": "Reconnaissance"
}


async def _get_profile(ip: str) -> dict:
    profile = await ueba_profiles_collection.find_one({"ip_address": ip})
    if profile:
        return profile
    profile = {
        "ip_address": ip,
        "first_seen": None,
        "last_seen": None,
        "total_events": 0,
        "failed_events": 0,
        "invalid_events": 0,
        "success_events": 0,
        "avg_events_per_window": 0.0,
        "avg_daily_events": 0.0,
        "last_day": None,
        "today_count": 0,
        "current_session_start": None,
        "current_session_events": 0,
        "last_incident_at": None
    }
    await ueba_profiles_collection.insert_one(profile)
    return profile


async def _get_user_profile(username: str) -> dict:
    profile = await ueba_user_profiles_collection.find_one({"username": username})
    if profile:
        return profile
    profile = {
        "username": username,
        "first_seen": None,
        "last_seen": None,
        "total_events": 0,
        "avg_daily_events": 0.0,
        "last_day": None,
        "today_count": 0,
        "last_incident_at": None
    }
    await ueba_user_profiles_collection.insert_one(profile)
    return profile


async def _update_profile(ip: str, updates: dict):
    await ueba_profiles_collection.update_one(
        {"ip_address": ip},
        {"$set": updates}
    )


async def _update_user_profile(username: str, updates: dict):
    await ueba_user_profiles_collection.update_one(
        {"username": username},
        {"$set": updates}
    )


async def _window_counts(ip: str, window_start: datetime) -> dict:
    pipeline = [
        {"$match": {
            "ip_address": ip,
            "event_time": {"$gte": window_start}
        }},
        {"$group": {
            "_id": "$event_type",
            "count": {"$sum": 1}
        }}
    ]
    counts = {"total": 0, "failed": 0, "invalid": 0, "success": 0}
    async for row in logs_collection.aggregate(pipeline):
        counts["total"] += row["count"]
        if row["_id"] == "ssh_failed_login":
            counts["failed"] = row["count"]
        elif row["_id"] == "ssh_invalid_user":
            counts["invalid"] = row["count"]
        elif row["_id"] == "ssh_success_login":
            counts["success"] = row["count"]
    return counts


async def _user_multi_source(username: str, window_start: datetime) -> int:
    if not username:
        return 0
    pipeline = [
        {"$match": {
            "username": username,
            "event_time": {"$gte": window_start}
        }},
        {"$group": {
            "_id": "$ip_address"
        }}
    ]
    count = 0
    async for _ in logs_collection.aggregate(pipeline):
        count += 1
    return count


async def _roll_session(profile: dict, now: datetime):
    last_seen = profile.get("last_seen")
    current_start = profile.get("current_session_start")
    current_events = profile.get("current_session_events", 0)

    if last_seen and current_start:
        gap = now - last_seen
        if gap > timedelta(minutes=SESSION_GAP_MINUTES):
            await ueba_sessions_collection.insert_one({
                "ip_address": profile["ip_address"],
                "start": current_start,
                "end": last_seen,
                "event_count": current_events
            })
            return {
                "current_session_start": now,
                "current_session_events": 0
            }

    if not current_start:
        return {
            "current_session_start": now,
            "current_session_events": 0
        }

    return {}


async def record_event(event: dict) -> dict | None:
    ip = event.get("ip_address")
    username = event.get("username")
    if not ip:
        return None

    now = event.get("event_time") or datetime.now(timezone.utc)
    profile = await _get_profile(ip)

    updates = {
        "first_seen": profile["first_seen"] or now,
        "last_seen": now,
        "total_events": profile["total_events"] + 1
    }

    session_updates = await _roll_session(profile, now)
    updates.update(session_updates)
    updates["current_session_events"] = updates.get(
        "current_session_events",
        profile.get("current_session_events", 0)
    ) + 1

    day_key = now.date().isoformat()
    last_day = profile.get("last_day")
    today_count = profile.get("today_count", 0)
    avg_daily = profile.get("avg_daily_events", 0.0)

    if last_day and last_day != day_key:
        avg_daily = (1 - EMA_ALPHA) * avg_daily + EMA_ALPHA * today_count
        today_count = 0

    today_count += 1
    updates["last_day"] = day_key
    updates["today_count"] = today_count
    updates["avg_daily_events"] = avg_daily

    event_type = event.get("event_type")
    if event_type == "ssh_failed_login":
        updates["failed_events"] = profile["failed_events"] + 1
    elif event_type == "ssh_invalid_user":
        updates["invalid_events"] = profile["invalid_events"] + 1
    elif event_type == "ssh_success_login":
        updates["success_events"] = profile["success_events"] + 1

    await _update_profile(ip, updates)

    # Update user profile
    if username:
        user = await _get_user_profile(username)
        user_day = user.get("last_day")
        user_today = user.get("today_count", 0)
        user_avg = user.get("avg_daily_events", 0.0)
        if user_day and user_day != day_key:
            user_avg = (1 - EMA_ALPHA) * user_avg + EMA_ALPHA * user_today
            user_today = 0
        user_today += 1
        await _update_user_profile(username, {
            "first_seen": user["first_seen"] or now,
            "last_seen": now,
            "total_events": user["total_events"] + 1,
            "last_day": day_key,
            "today_count": user_today,
            "avg_daily_events": user_avg
        })

    # Rare entity detection (first time seen)
    if profile["total_events"] == 0:
        return {
            "alert_type": "ueba_rare_entity",
            "incident": "UEBA: Rare Entity Observed",
            "confidence": "medium",
            "risk_score": 5,
            "mitre": {},
            "ip_address": ip,
            "severity": "medium",
            "kill_chain_stage": KILL_CHAIN["UEBA: Rare Entity Observed"],
            "description": f"New IP observed: {ip}",
            "timestamp": datetime.now(timezone.utc)
        }

    return None


def _decay_risk(prev_risk: float, minutes: float) -> float:
    return max(1.0, prev_risk - (minutes / 10.0))


async def _upsert_incident(incident_key: str, payload: dict) -> dict | None:
    existing = await ueba_incidents_collection.find_one({"incident_key": incident_key})
    now = payload["timestamp"]
    if not existing:
        payload["incident_key"] = incident_key
        await ueba_incidents_collection.insert_one(payload)
        return payload

    last = existing.get("last_seen") or existing.get("timestamp")
    minutes = (now - last).total_seconds() / 60.0
    risk = _decay_risk(existing.get("risk_score", 5), minutes)
    risk = max(risk, payload.get("risk_score", 5))

    await ueba_incidents_collection.update_one(
        {"incident_key": incident_key},
        {"$set": {
            "last_seen": now,
            "risk_score": risk,
            "event_count": payload.get("event_count", existing.get("event_count", 0)) + 1
        }}
    )

    if minutes < COOLDOWN_MINUTES:
        return None

    payload["risk_score"] = risk
    payload["incident_key"] = incident_key
    return payload


async def evaluate(event: dict) -> dict | None:
    ip = event.get("ip_address")
    username = event.get("username")
    if not ip:
        return None

    now = event.get("event_time") or datetime.now(timezone.utc)
    profile = await _get_profile(ip)

    if profile.get("last_incident_at"):
        if now - profile["last_incident_at"] < timedelta(minutes=COOLDOWN_MINUTES):
            return None

    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    counts = await _window_counts(ip, window_start)

    avg = profile.get("avg_events_per_window", 0.0)
    ema = (1 - EMA_ALPHA) * avg + EMA_ALPHA * counts["total"]

    burst = counts["total"] >= max(BURST_THRESHOLD, ema * 3)
    brute = counts["failed"] >= FAILED_THRESHOLD and counts["success"] == 0
    enum = counts["failed"] >= 3 and counts["invalid"] >= INVALID_THRESHOLD

    # Cross-entity: same user from multiple IPs in window
    multi_source = await _user_multi_source(username, window_start)
    multi_user = multi_source >= 2

    if not (burst or brute or enum or multi_user):
        await _update_profile(ip, {"avg_events_per_window": ema})
        return None

    if multi_user:
        incident = "UEBA: Multi-Source User Activity"
        base_incident = "Credential Enumeration"
        confidence = "medium"
    elif brute:
        incident = "UEBA: Persistent Brute Force"
        base_incident = "Brute Force Attack"
        confidence = "high"
    elif enum:
        incident = "UEBA: Credential Enumeration"
        base_incident = "Credential Enumeration"
        confidence = "medium"
    else:
        incident = "UEBA: Abnormal Activity Burst"
        base_incident = "Brute Force Attack"
        confidence = "medium"

    risk = calculate_risk(base_incident, max(counts["total"], counts["failed"]))
    mitre = get_mitre(base_incident) or {}
    severity = "high" if risk >= 8 else "medium"

    await _update_profile(ip, {
        "avg_events_per_window": ema,
        "last_incident_at": now
    })

    payload = {
        "alert_type": "ueba_incident",
        "incident": incident,
        "confidence": confidence,
        "risk_score": min(max(risk, 5), 10),
        "mitre": mitre,
        "ip_address": ip,
        "severity": severity,
        "kill_chain_stage": KILL_CHAIN.get(incident, "Unknown"),
        "description": (
            f"{incident} from {ip} (events={counts['total']}, "
            f"failed={counts['failed']}, invalid={counts['invalid']})"
        ),
        "window_minutes": WINDOW_MINUTES,
        "event_count": counts["total"],
        "baseline_window_avg": ema,
        "baseline_daily_avg": profile.get("avg_daily_events", 0.0),
        "first_seen": profile.get("first_seen"),
        "last_seen": now,
        "timestamp": datetime.now(timezone.utc)
    }

    incident_key = f"{incident}:{ip}"
    return await _upsert_incident(incident_key, payload)
