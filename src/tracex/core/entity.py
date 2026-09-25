from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.confidence import Confidence
from tracex.utils.clock import utcnow


class EntityType(StrEnum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    IP = "ip"
    SERVICE = "service"
    EXPOSURE = "exposure"


class Entity(BaseModel):
    type: EntityType
    value: str
    source: str
    confidence: Confidence = Confidence.UNKNOWN
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> tuple[EntityType, str]:
        return (self.type, self.value)