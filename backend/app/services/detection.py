from datetime import datetime, timedelta, timezone

from app.core.database import alerts_collection, logs_collection
from app.intel.mitre import get_mitre
from app.services.anomaly import detect_anomaly
from app.ml.anomaly import anomaly_model
from app.services.correlation import correlator
from app.services.scoring import calculate_risk
from app.ws.alerts import manager
from app.services import ueba

FAILED_THRESHOLD = 5
WINDOW_MINUTES = 2


async def broadcast_alert(alert_dict: dict):
    await manager.broadcast({
        "type": "new_alert",
        "data": alert_dict
    })


async def process_event(event: dict):
    rare_alert = await ueba.record_event(event)
    correlator.add_event(event)
    result = correlator.evaluate(event["ip_address"])

    # Anomaly check
    is_anomaly, anomaly_score = await detect_anomaly(event)
    if is_anomaly:
        now = datetime.now(timezone.utc)
        alert = {
            "alert_type": "anomaly_detected",
            "ip_address": event["ip_address"],
            "severity": "high",
            "description": "Abnormal activity detected from IP",
            "anomaly_score": anomaly_score,
            "ml_model": "isolation_forest",
            "ml_version": anomaly_model.model_version,
            "timestamp": now
        }

        await alerts_collection.insert_one(alert)
        await broadcast_alert(alert)

    if rare_alert:
        await alerts_collection.insert_one(rare_alert)
        await broadcast_alert(rare_alert)

    ueba_alert = await ueba.evaluate(event)
    if ueba_alert:
        await alerts_collection.insert_one(ueba_alert)
        await broadcast_alert(ueba_alert)

    if result:
        now = datetime.now(timezone.utc)
        event_count = result.get("count", 1)
        risk = calculate_risk(result["incident"], event_count)
        mitre = get_mitre(result["incident"])
        severity = "high" if risk >= 8 else "medium" if risk >= 5 else "low"

        alert = {
            "alert_type": "correlated_incident",
            "incident": result["incident"],
            "confidence": result["confidence"],
            "risk_score": risk,
            "mitre": mitre,
            "ip_address": event["ip_address"],
            "severity": severity,
            "description": f"{result['incident']} from {event['ip_address']}",
            "timestamp": now
        }

        await alerts_collection.insert_one(alert)
        await broadcast_alert(alert)

        return alert


async def check_ssh_bruteforce(ip_address: str):
    time_window = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)

    count = await logs_collection.count_documents({
        "ip_address": ip_address,
        "event_type": "ssh_failed_login",
        "timestamp": {"$gte": time_window}
    })

    if count >= FAILED_THRESHOLD:
        alert = {
            "timestamp": datetime.now(timezone.utc),
            "alert_type": "ssh_bruteforce",
            "ip_address": ip_address,
            "count": count,
            "severity": "high",
            "description": f"Detected SSH brute force from {ip_address}"
        }

        existing = await alerts_collection.find_one({
            "alert_type": "ssh_bruteforce",
            "ip_address": ip_address,
            "timestamp": {"$gte": time_window}
        })

        if not existing:
            await alerts_collection.insert_one(alert)
            return alert

    return None
