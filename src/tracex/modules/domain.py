from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.engine import run_sources
from tracex.core.result import SourceResult
from tracex.core.target import Target
from tracex.modules.email import Check, _domain_check, _presence_check
from tracex.sources.ct import CrtShSource
from tracex.sources.dns import DnsSource
from tracex.sources.mailsec import MailSecSource
from tracex.utils.clock import utcnow
from tracex.utils.dnsclient import DnsClient
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tracex.storage.cache import Cache

class DomainReport(BaseModel):
    target: Target
    exists: Check
    spf: Check
    dmarc: Check
    subdomains: list[str] = Field(default_factory=list)
    results: list[SourceResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)

    def to_payload(self) -> dict[str, Any]:
        return {
            "target": self.target.model_dump(mode="json"),
            "checks": {"exists": self.exists.value, "spf": self.spf.value, "dmarc": self.dmarc.value},
            "subdomains": self.subdomains,
            "findings": [f.model_dump(mode="json") for r in self.results for f in r.findings],
            "entities": [e.model_dump(mode="json") for r in self.results for e in r.entities],
            "sources": [
                {"name": r.source, "status": r.status.value, "elapsed_ms": r.elapsed_ms, "error": r.error}
                for r in self.results
            ],
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), indent=2, ensure_ascii=False)


async def analyze_domain(
    target: Target,
    timeout: float = 10.0,
    dns_client: DnsClient | None = None,
    cache: "Cache | None" = None,
) -> DomainReport:
    client = dns_client or DnsClient(timeout=min(timeout, 5.0))
    adapters = [DnsSource(client), MailSecSource(client), CrtShSource()]
    results = await run_sources(target, adapters, timeout=timeout, cache=cache)
    by_name = {r.source: r for r in results}
    dns_res, ms_res, ct_res = by_name.get("dns"), by_name.get("mailsec"), by_name.get("crtsh")

    subdomains = ct_res.data.get("hostnames", []) if ct_res else []

    return DomainReport(
        target=target,
        exists=_domain_check(dns_res),
        spf=_presence_check(ms_res, "spf"),
        dmarc=_presence_check(ms_res, "dmarc"),
        subdomains=subdomains,
        results=results,
    )