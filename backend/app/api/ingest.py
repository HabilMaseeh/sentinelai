from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from app.services.parser import parse_auth_log
from app.schemas.log import RawLogRequest
from app.services.storage import save_log
from app.services.detection import process_event
from app.ml.severity import infer_severity

router = APIRouter()

@router.post("/ingest")
async def ingest_log(payload: RawLogRequest):
    parsed = parse_auth_log(payload.raw_log)

    if not parsed:
        raise HTTPException(status_code=400, detail="Unrecognized log format")

    now = datetime.now(timezone.utc)
    parsed["event_time"] = parsed.get("event_time") or now
    parsed["ingested_at"] = now
    parsed["timestamp"] = now
    parsed["severity"] = infer_severity(parsed)

    log_id = await save_log(parsed)

    alert = None
    if parsed.get("ip_address"):
        alert = await process_event(parsed)

    return {
        "status": "stored",
        "log_id": log_id,
        "alert": alert
    }
