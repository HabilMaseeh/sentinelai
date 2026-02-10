from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Query

from app.core.database import logs_collection
from app.ml.anomaly import anomaly_model, FEATURE_NAMES
from app.services.anomaly import extract_features

router = APIRouter()


async def run_training(days: int, limit: int) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    cursor = logs_collection.find(
        {"event_time": {"$gte": since}},
        {"event_time": 1, "event_type": 1, "ip_address": 1, "username": 1}
    ).limit(limit)

    features = []
    async for log in cursor:
        if not log.get("event_time"):
            continue
        features.append(await extract_features(log))

    anomaly_model.train(features)

    return {
        "trained": anomaly_model.trained,
        "samples": len(features),
        "model_version": anomaly_model.model_version,
        "last_trained_at": anomaly_model.last_trained_at,
        "feature_names": FEATURE_NAMES,
    }


@router.post("/ml/train")
async def train_anomaly_model(
    days: int = Query(7, ge=1, le=30),
    limit: int = Query(1000, ge=100, le=10000),
):
    return await run_training(days, limit)


@router.get("/ml/status")
async def ml_status():
    return {
        "trained": anomaly_model.trained,
        "model_version": anomaly_model.model_version,
        "last_trained_at": anomaly_model.last_trained_at,
        "last_train_samples": anomaly_model.last_train_samples,
        "feature_names": FEATURE_NAMES,
    }
