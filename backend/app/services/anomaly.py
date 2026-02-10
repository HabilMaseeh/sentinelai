from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import math

from app.core.database import logs_collection
from app.ml.anomaly import anomaly_model

WINDOW_2M = timedelta(minutes=2)
WINDOW_5M = timedelta(minutes=5)
WINDOW_1H = timedelta(hours=1)
WINDOW_24H = timedelta(hours=24)


async def extract_features(event: dict) -> dict:
    now = event.get("event_time") or datetime.now(timezone.utc)
    ip = event.get("ip_address")
    username = event.get("username")

    window_2m = now - WINDOW_2M
    window_5m = now - WINDOW_5M
    window_1h = now - WINDOW_1H
    window_24h = now - WINDOW_24H

    hour = now.hour
    hour_angle = (2 * math.pi * hour) / 24.0

    failed_attempts = 0
    success_attempts = 0
    event_rate = 0
    unique_users = []
    unique_ips_5m = []
    unique_ips_1h = []

    if ip:
        base_ip_query_2m = {"ip_address": ip, "event_time": {"$gte": window_2m}}
        base_ip_query_5m = {"ip_address": ip, "event_time": {"$gte": window_5m}}

        failed_attempts = await logs_collection.count_documents({
            **base_ip_query_2m,
            "event_type": "ssh_failed_login",
        })
        success_attempts = await logs_collection.count_documents({
            **base_ip_query_2m,
            "event_type": "ssh_success_login",
        })
        event_rate = await logs_collection.count_documents(base_ip_query_2m)

        unique_users = await logs_collection.distinct("username", base_ip_query_5m)
        unique_users = [u for u in unique_users if u]

    if username:
        unique_ips_5m = await logs_collection.distinct(
            "ip_address",
            {"username": username, "event_time": {"$gte": window_5m}},
        )
        unique_ips_5m = [i for i in unique_ips_5m if i]

        unique_ips_1h = await logs_collection.distinct(
            "ip_address",
            {"username": username, "event_time": {"$gte": window_1h}},
        )
        unique_ips_1h = [i for i in unique_ips_1h if i]

        user_event_rate_1h = await logs_collection.count_documents({
            "username": username,
            "event_time": {"$gte": window_1h},
        })
        user_failed_1h = await logs_collection.count_documents({
            "username": username,
            "event_time": {"$gte": window_1h},
            "event_type": "ssh_failed_login",
        })
        user_success_1h = await logs_collection.count_documents({
            "username": username,
            "event_time": {"$gte": window_1h},
            "event_type": "ssh_success_login",
        })

        user_event_rate_24h = await logs_collection.count_documents({
            "username": username,
            "event_time": {"$gte": window_24h},
        })
        user_failed_24h = await logs_collection.count_documents({
            "username": username,
            "event_time": {"$gte": window_24h},
            "event_type": "ssh_failed_login",
        })
        user_failed_ratio_24h = user_failed_24h / max(1, user_event_rate_24h)
    else:
        user_event_rate_1h = 0
        user_failed_1h = 0
        user_success_1h = 0
        user_event_rate_24h = 0
        user_failed_ratio_24h = 0

    ip_is_private = 0
    ip_is_reserved = 0
    ip_is_global = 0

    if ip:
        try:
            addr = ip_address(ip)
            ip_is_private = 1 if addr.is_private else 0
            ip_is_reserved = 1 if addr.is_reserved else 0
            ip_is_global = 1 if addr.is_global else 0
        except ValueError:
            pass

    return {
        "hour": hour,
        "hour_sin": math.sin(hour_angle),
        "hour_cos": math.cos(hour_angle),
        "failed_attempts_2m": failed_attempts,
        "success_attempts_2m": success_attempts,
        "event_rate_2m": event_rate,
        "unique_users_5m": len(unique_users),
        "unique_ips_5m": len(unique_ips_5m),
        "user_event_rate_1h": user_event_rate_1h,
        "user_failed_1h": user_failed_1h,
        "user_success_1h": user_success_1h,
        "user_unique_ips_1h": len(unique_ips_1h),
        "user_event_rate_24h": user_event_rate_24h,
        "user_failed_ratio_24h": user_failed_ratio_24h,
        "ip_is_private": ip_is_private,
        "ip_is_reserved": ip_is_reserved,
        "ip_is_global": ip_is_global,
    }


async def detect_anomaly(event: dict) -> tuple[bool, float | None]:
    if not anomaly_model.trained:
        return False, None

    features = await extract_features(event)
    is_anomaly, score = anomaly_model.predict(features)
    return is_anomaly, score
