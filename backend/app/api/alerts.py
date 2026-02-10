from fastapi import APIRouter, Query
from app.core.database import alerts_collection

router = APIRouter()

@router.get("/alerts")
async def get_alerts(
    severity: str | None = None,
    limit: int = Query(50, le=200)
):
    query = {}
    if severity:
        query["severity"] = severity

    cursor = alerts_collection.find(query).sort("timestamp", -1).limit(limit)
    alerts = []

    async for alert in cursor:
        alert["_id"] = str(alert["_id"])
        alerts.append(alert)

    return alerts
