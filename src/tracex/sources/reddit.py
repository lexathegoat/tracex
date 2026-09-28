from __future__ import annotations

from typing import Any

import httpx

from tracex.core.confidence import Confidence
from tracex.core.entity import Entity, EntityType
from tracex.core.errors import SourceError
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

_HEADERS = {"User-Agent": "tracex-osint-tool/0.2 (passive lookup)"}


class RedditSource(SourceAdapter):
    name = "reddit"
    supported_targets = frozenset({TargetType.USERNAME})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def query(self, target: Target) -> dict[str, Any]:
        client = self._client or httpx.AsyncClient()
        try:
            resp = await client.get(
                f"https://www.reddit.com/user/{target.value}/about.json", headers=_HEADERS
            )
        finally:
            if self._client is None:
                await client.aclose()

        if resp.status_code == 404:
            return {"found": False}
        if resp.status_code == 429:
            raise SourceError(SourceStatus.RATE_LIMITED, "Reddit rate limit exceeded")
        if resp.status_code != 200:
            raise SourceError(SourceStatus.SOURCE_ERROR, f"HTTP {resp.status_code}")
        return {"found": True, "profile": resp.json().get("data", {})}

    def normalize(self, target: Target, raw: dict[str, Any]) -> SourceResult:
        if not raw["found"]:
            return SourceResult(source=self.name, target=target, status=SourceStatus.NOT_FOUND)

        profile = raw["profile"]
        if profile.get("is_suspended"):
            return SourceResult(
                source=self.name, target=target, status=SourceStatus.FOUND,
                findings=[Finding(title="Reddit account suspended", source=self.name,
                                  source_confidence=Confidence.HIGH)],
                data=profile,
            )

        entities = [Entity(
            type=EntityType.USERNAME, value=target.value, source=self.name,
            confidence=Confidence.HIGH,
            metadata={"platform": "reddit", "url": f"https://reddit.com/user/{target.value}"},
        )]
        findings = [Finding(
            title="Reddit profile found",
            detail=f"karma: {profile.get('total_karma', '?')}",
            source=self.name, source_confidence=Confidence.HIGH,
            association_confidence=Confidence.MEDIUM,
            data={"created_utc": profile.get("created_utc")},
        )]
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND,
                            findings=findings, entities=entities, data=profile)