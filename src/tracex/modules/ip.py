from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.engine import run_sources
from tracex.core.result import SourceResult
from tracex.core.target import Target
from tracex.sources.ipapi import IpApiSource
from tracex.sources.reverse_dns import ReverseDnsSource
from tracex.utils.clock import utcnow
from tracex.utils.dnsclient import DnsClient


class IpReport(BaseModel):
    target: Target
    reverse_dns: list[str] = Field(default_factory=list)
    results: list[SourceResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)

    def to_payload(self) -> dict[str, Any]:
        return {
            "target": self.target.model_dump(mode="json"),
            "reverse_dns": self.reverse_dns,
            "findings": [f.model_dump(mode="json") for r in self.results for f in r.findings],
            "sources": [
                {"name": r.source, "status": r.status.value, "elapsed_ms": r.elapsed_ms, "error": r.error}
                for r in self.results
            ],
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), indent=2, ensure_ascii=False)


async def analyze_ip(
    target: Target,
    timeout: float = 10.0,
    dns_client: DnsClient | None = None,
) -> IpReport:
    client = dns_client or DnsClient(timeout=min(timeout, 5.0))
    results = await run_sources(target, [ReverseDnsSource(client), IpApiSource()], timeout=timeout)
    rdns = next((r for r in results if r.source == "reverse_dns"), None)
    return IpReport(
        target=target,
        reverse_dns=rdns.data.get("ptr", []) if rdns else [],
        results=results,
    )