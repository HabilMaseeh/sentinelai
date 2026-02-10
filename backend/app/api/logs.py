from fastapi import APIRouter, Query
from app.core.database import logs_collection

router = APIRouter()

@router.get("/logs")
async def get_logs(
    ip: str | None = None,
    user: str | None = None,
    limit: int = Query(100, le=500)
):
    query = {}

    if ip:
        query["ip_address"] = ip
    if user:
        query["username"] = user

    cursor = logs_collection.find(query).sort("timestamp", -1).limit(limit)
    logs = []

    async for log in cursor:
        log["_id"] = str(log["_id"])
        logs.append(log)

    return logs
