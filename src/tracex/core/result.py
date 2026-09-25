from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.entity import Entity
from tracex.core.finding import Finding
from tracex.core.status import SourceStatus
from tracex.core.target import Target
from tracex.utils.clock import utcnow


class SourceResult(BaseModel):
    source: str
    target: Target
    status: SourceStatus
    findings: list[Finding] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict) 
    error: str | None = None
    elapsed_ms: int = 0
    cached: bool = False
    timestamp: datetime = Field(default_factory=utcnow)