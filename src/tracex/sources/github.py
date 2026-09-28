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


class GitHubSource(SourceAdapter):
    name = "github"
    supported_targets = frozenset({TargetType.USERNAME})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def query(self, target: Target) -> dict[str, Any]:
        client = self._client or httpx.AsyncClient()
        try:
            resp = await client.get(f"https://api.github.com/users/{target.value}")
        finally:
            if self._client is None:
                await client.aclose()

        if resp.status_code == 404:
            return {"found": False}
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            raise SourceError(SourceStatus.RATE_LIMITED, "GitHub API rate limit exceeded")
        if resp.status_code != 200:
            raise SourceError(SourceStatus.SOURCE_ERROR, f"HTTP {resp.status_code}")
        return {"found": True, "profile": resp.json()}

    def normalize(self, target: Target, raw: dict[str, Any]) -> SourceResult:
        if not raw["found"]:
            return SourceResult(source=self.name, target=target, status=SourceStatus.NOT_FOUND)

        profile = raw["profile"]
        entities = [Entity(
            type=EntityType.USERNAME, value=target.value, source=self.name,
            confidence=Confidence.HIGH,
            metadata={"platform": "github", "url": profile.get("html_url")},
        )]
        detail = " · ".join(
            p for p in (profile.get("name"), profile.get("company"), profile.get("location")) if p
        ) or profile.get("html_url", "")
        findings = [Finding(
            title="GitHub profile found", detail=detail,
            source=self.name, source_confidence=Confidence.HIGH,
            association_confidence=Confidence.MEDIUM,  # same username != proven same person
            data={"public_repos": profile.get("public_repos"), "followers": profile.get("followers")},
        )]
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND,
                            findings=findings, entities=entities, data=profile)