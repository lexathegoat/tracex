from __future__ import annotations

import httpx

from tracex.core.confidence import Confidence
from tracex.core.entity import Entity, EntityType
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

CRT_SH_URL = "https://crt.sh/"


def parse_hostnames(records: list[dict], domain: str) -> list[str]:
    names: set[str] = set()
    for row in records:
        for name in row.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith(f".{domain}")):
                names.add(name)
    return sorted(names)


class CrtShSource(SourceAdapter):
    name = "crtsh"
    supported_targets = frozenset({TargetType.DOMAIN, TargetType.EMAIL})

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    async def query(self, target: Target) -> list[dict]:
        domain = target.domain
        assert domain is not None
        client = self._client or httpx.AsyncClient()
        try:
            resp = await client.get(
                CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"}
            )
            resp.raise_for_status()
            text = resp.text.strip()
            if not text:
                return []
            import json

            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return json.loads(f"[{text.replace('}{', '},{')}]")
        finally:
            if self._client is None:
                await client.aclose()

    def normalize(self, target: Target, raw: list[dict]) -> SourceResult:
        domain = target.domain
        assert domain is not None
        hostnames = parse_hostnames(raw, domain)

        entities = [
            Entity(
                type=EntityType.HOSTNAME, value=host, source=self.name,
                confidence=Confidence.MEDIUM,
                metadata={"via": "certificate_transparency"},
            )
            for host in hostnames
        ]
        findings = [Finding(
            title="Subdomains observed in CT logs",
            detail=f"{len(hostnames)} hostname(s)",
            source=self.name, source_confidence=Confidence.MEDIUM,
            data={"hostnames": hostnames},
        )]

        return SourceResult(
            source=self.name, target=target,
            status=SourceStatus.FOUND if hostnames else SourceStatus.NOT_FOUND,
            findings=findings, entities=entities, data={"hostnames": hostnames},
        )
