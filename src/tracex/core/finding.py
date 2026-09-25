from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.confidence import Confidence
from tracex.core.status import SourceStatus
from tracex.utils.clock import utcnow


class Finding(BaseModel):
    title: str
    detail: str = ""
    source: str
    status: SourceStatus = SourceStatus.FOUND
    source_confidence: Confidence = Confidence.UNKNOWN
    association_confidence: Confidence | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    data: dict[str, Any] = Field(default_factory=dict)
