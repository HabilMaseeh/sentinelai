from pydantic import BaseModel
from datetime import datetime


class LogSchema(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    username: str | None = None
    ip_address: str | None = None
    message: str
    severity: str
    metadata: dict | None = None

class RawLogRequest(BaseModel):
    raw_log: str