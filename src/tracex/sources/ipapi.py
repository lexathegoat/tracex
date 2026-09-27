from __future__ import annotations

from typing import Any

import httpx

from tracex.core.confidence import Confidence
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

IPAPI_URL = "http://ip-api.com/json/{ip}"
FIELDS = "status,message,country,regionName,city,isp,org,as,reverse,hosting,proxy,query"


class IpApiSource(SourceAdapter):
    """Passive IP geolocation/ASN lookup via ip-api.com."""

    name = "ipapi"
    supported_targets = frozenset({TargetType.IP})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def query(self, target: Target) -> dict[str, Any]:
        client = self._client or httpx.AsyncClient()
        try:
            resp = await client.get(
                IPAPI_URL.format(ip=target.value), params={"fields": FIELDS}
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            if self._client is None:
                await client.aclose()

    def normalize(self, target: Target, raw: dict[str, Any]) -> SourceResult:
        if raw.get("status") != "success":
            return SourceResult(
                source=self.name, target=target, status=SourceStatus.NOT_FOUND,
                error=raw.get("message", "lookup failed"),
            )
        findings = [
            Finding(
                title="ASN / organization", detail=f"{raw.get('as', '?')} — {raw.get('org', '?')}",
                source=self.name, source_confidence=Confidence.MEDIUM, data=raw,
            ),
            Finding(
                title="Location", detail=f"{raw.get('city', '?')}, {raw.get('regionName', '?')}, {raw.get('country', '?')}",
                source=self.name, source_confidence=Confidence.LOW,  # IP geolocation is often inaccurate
            ),
        ]
        if raw.get("hosting"):
            findings.append(Finding(
                title="Hosting/datacenter IP", source=self.name,
                source_confidence=Confidence.MEDIUM,
            ))
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND,
                            findings=findings, data=raw)