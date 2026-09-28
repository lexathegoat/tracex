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


class GitLabSource(SourceAdapter):
    name = "gitlab"
    supported_targets = frozenset({TargetType.USERNAME})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def query(self, target: Target) -> list[dict[str, Any]]:
        client = self._client or httpx.AsyncClient()
        try:
            resp = await client.get(
                "https://gitlab.com/api/v4/users", params={"username": target.value}
            )
        finally:
            if self._client is None:
                await client.aclose()

        if resp.status_code == 429:
            raise SourceError(SourceStatus.RATE_LIMITED, "GitLab API rate limit exceeded")
        if resp.status_code != 200:
            raise SourceError(SourceStatus.SOURCE_ERROR, f"HTTP {resp.status_code}")
        return resp.json()

    def normalize(self, target: Target, raw: list[dict[str, Any]]) -> SourceResult:
        # GitLab's username search can match substrings; keep exact matches only.
        matches = [u for u in raw if u.get("username", "").lower() == target.value.lower()]
        if not matches:
            return SourceResult(source=self.name, target=target, status=SourceStatus.NOT_FOUND)

        profile = matches[0]
        entities = [Entity(
            type=EntityType.USERNAME, value=target.value, source=self.name,
            confidence=Confidence.HIGH,
            metadata={"platform": "gitlab", "url": profile.get("web_url")},
        )]
        findings = [Finding(
            title="GitLab profile found",
            detail=profile.get("name", "") or profile.get("web_url", ""),
            source=self.name, source_confidence=Confidence.HIGH,
            association_confidence=Confidence.MEDIUM,
            data={"state": profile.get("state")},
        )]
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND,
                            findings=findings, entities=entities, data=profile)