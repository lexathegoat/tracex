from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from tracex.core.engine import run_sources
from tracex.core.result import SourceResult
from tracex.core.target import Target
from tracex.sources.github import GitHubSource
from tracex.sources.gitlab import GitLabSource
from tracex.sources.reddit import RedditSource
from tracex.utils.clock import utcnow

if TYPE_CHECKING:
    from tracex.storage.cache import Cache


class UsernameReport(BaseModel):
    target: Target
    results: list[SourceResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)

    def to_payload(self) -> dict[str, Any]:
        return {
            "target": self.target.model_dump(mode="json"),
            "sources": [
                {"name": r.source, "status": r.status.value, "elapsed_ms": r.elapsed_ms, "error": r.error}
                for r in self.results
            ],
            "findings": [f.model_dump(mode="json") for r in self.results for f in r.findings],
            "entities": [e.model_dump(mode="json") for r in self.results for e in r.entities],
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), indent=2, ensure_ascii=False)


async def analyze_username(
    target: Target,
    timeout: float = 10.0,
    cache: "Cache | None" = None,
) -> UsernameReport:
    adapters = [GitHubSource(), GitLabSource(), RedditSource()]
    results = await run_sources(target, adapters, timeout=timeout, cache=cache)
    return UsernameReport(target=target, results=results)