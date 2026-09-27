from __future__ import annotations

from tracex.core.confidence import Confidence
from tracex.core.entity import Entity, EntityType
from tracex.core.errors import NXDomainError, SourceError
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType


class ReverseDnsSource(SourceAdapter):
    name = "reverse_dns"
    supported_targets = frozenset({TargetType.IP})

    def __init__(self, client) -> None:
        self._client = client

    async def query(self, target: Target) -> list[str]:
        try:
            return await self._client.reverse_lookup(target.value)
        except NXDomainError:
            return []

    def normalize(self, target: Target, raw: list[str]) -> SourceResult:
        if not raw:
            return SourceResult(source=self.name, target=target, status=SourceStatus.NOT_FOUND)
        entities = [
            Entity(type=EntityType.HOSTNAME, value=host.rstrip("."), source=self.name,
                  confidence=Confidence.HIGH, metadata={"role": "ptr", "ip": target.value})
            for host in raw
        ]
        findings = [Finding(
            title="Reverse DNS (PTR) record", detail=", ".join(raw),
            source=self.name, source_confidence=Confidence.HIGH,
        )]
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND,
                            findings=findings, entities=entities, data={"ptr": raw})