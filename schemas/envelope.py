from pydantic import BaseModel
from typing import Literal
from datetime import datetime


class EventEnvelope(BaseModel):
    schema_version: str
    event_id: str
    event_type: str
    timestamp: datetime
    producer: str
    severity: Literal["info", "low", "medium", "high", "critical"]
