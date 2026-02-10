import os


async def lookup_ip(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "unconfigured"}

    try:
        import httpx
    except Exception:
        return {"status": "missing_http_client"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                return {"status": "error", "code": resp.status_code}
            return {"status": "ok", "data": resp.json().get("data", {})}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
