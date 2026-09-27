from __future__ import annotations

import asyncio
from typing import Any

from tracex.core.confidence import Confidence
from tracex.core.entity import Entity, EntityType
from tracex.core.errors import NXDomainError, SourceError
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DnsSource(SourceAdapter):
    name = "dns"
    supported_targets = frozenset({TargetType.DOMAIN, TargetType.EMAIL})

    def __init__(self, client) -> None:
        self._client = client

    async def query(self, target: Target) -> dict[str, Any]:
        domain = target.domain
        assert domain is not None
        raw: dict[str, Any] = {"domain": domain, "nxdomain": False, "records": {}, "errors": {}}
        outcomes = await asyncio.gather(
            *(self._client.lookup(domain, rt) for rt in RECORD_TYPES),
            return_exceptions=True,
        )
        for rtype, outcome in zip(RECORD_TYPES, outcomes):
            if isinstance(outcome, NXDomainError):
                raw["nxdomain"] = True
            elif isinstance(outcome, SourceError):
                raw["errors"][rtype] = outcome.status.value
            elif isinstance(outcome, Exception):
                raw["errors"][rtype] = type(outcome).__name__
            else:
                raw["records"][rtype] = outcome
        return raw

    def normalize(self, target: Target, raw: dict[str, Any]) -> SourceResult:
        errors = "; ".join(f"{k}={v}" for k, v in raw["errors"].items()) or None
        if raw["nxdomain"]:
            return SourceResult(
                source=self.name, target=target, status=SourceStatus.NOT_FOUND,
                error="NXDOMAIN", data=raw,
            )

        records = {k: v for k, v in raw["records"].items() if v}
        findings = [
            Finding(
                title=f"{rtype} records",
                detail=", ".join(values),
                source=self.name,
                source_confidence=Confidence.HIGH,
                data={"type": rtype, "values": values},
            )
            for rtype, values in records.items()
        ]

        entities: list[Entity] = []
        for ip in records.get("A", []) + records.get("AAAA", []):
            entities.append(Entity(
                type=EntityType.IP, value=ip, source=self.name,
                confidence=Confidence.HIGH, metadata={"resolved_from": raw["domain"]},
            ))
        for mx in records.get("MX", []):
            host = mx.split(maxsplit=1)[1]
            entities.append(Entity(
                type=EntityType.HOSTNAME, value=host, source=self.name,
                confidence=Confidence.HIGH, metadata={"role": "mx", "domain": raw["domain"]},
            ))

        if records:
            status = SourceStatus.FOUND
        elif raw["errors"]:
            status = SourceStatus.UNKNOWN  # we could not get an answer: NOT the same as "no records"
        else:
            status = SourceStatus.NOT_FOUND

        return SourceResult(
            source=self.name, target=target, status=status,
            findings=findings, entities=entities, data=raw, error=errors,
        )