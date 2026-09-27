from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tracex.core.engine import run_sources
from tracex.core.result import SourceResult
from tracex.core.status import SourceStatus
from tracex.core.target import Target
from tracex.sources.dns import DnsSource
from tracex.sources.mailsec import MailSecSource
from tracex.utils.clock import utcnow
from tracex.utils.dnsclient import DnsClient


class Check(StrEnum):
    OK = "ok"
    FAIL = "fail"
    UNKNOWN = "unknown"  # could not determine: NOT the same as fail


CHECK_NAMES = ("format", "local_part", "domain", "mx", "spf", "dmarc", "dkim")


class EmailReport(BaseModel):
    target: Target
    format: Check
    local_part: Check
    domain: Check
    mx: Check
    spf: Check
    dmarc: Check
    dkim: Check
    results: list[SourceResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)

    def to_payload(self) -> dict[str, Any]:
        return {
            "target": self.target.model_dump(mode="json"),
            "checks": {name: getattr(self, name).value for name in CHECK_NAMES},
            "findings": [f.model_dump(mode="json") for r in self.results for f in r.findings],
            "entities": [e.model_dump(mode="json") for r in self.results for e in r.entities],
            "sources": [
                {"name": r.source, "status": r.status.value,
                 "elapsed_ms": r.elapsed_ms, "error": r.error}
                for r in self.results
            ],
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), indent=2, ensure_ascii=False)


def _unusable(result: SourceResult | None) -> bool:
    return result is None or result.status.is_failure or result.status is SourceStatus.UNKNOWN


def _domain_check(dns: SourceResult | None) -> Check:
    if _unusable(dns):
        return Check.UNKNOWN
    return Check.FAIL if dns.data.get("nxdomain") else Check.OK


def _mx_check(dns: SourceResult | None) -> Check:
    if _unusable(dns):
        return Check.UNKNOWN
    records = dns.data.get("records", {})
    if records.get("MX"):
        return Check.OK
    if records.get("A") or records.get("AAAA"):
        return Check.UNKNOWN  # no MX, but implicit-MX fallback to A/AAAA is possible
    return Check.FAIL


def _presence_check(ms: SourceResult | None, key: str) -> Check:
    if _unusable(ms):
        return Check.UNKNOWN
    return Check.OK if ms.data.get(key) else Check.FAIL


def _dkim_check(ms: SourceResult | None) -> Check:
    if _unusable(ms):
        return Check.UNKNOWN
    # Not found among common selectors != no DKIM. Only a hit is conclusive.
    return Check.OK if ms.data.get("dkim_selectors") else Check.UNKNOWN


async def analyze_email(
    target: Target,
    timeout: float = 10.0,
    dns_client: DnsClient | None = None,
) -> EmailReport:
    client = dns_client or DnsClient(timeout=min(timeout, 5.0))
    results = await run_sources(target, [DnsSource(client), MailSecSource(client)], timeout=timeout)
    by_name = {r.source: r for r in results}
    dns, ms = by_name.get("dns"), by_name.get("mailsec")

    return EmailReport(
        target=target,
        format=Check.OK,       # Target.parse() already rejected invalid syntax
        local_part=Check.OK,
        domain=_domain_check(dns),
        mx=_mx_check(dns),
        spf=_presence_check(ms, "spf"),
        dmarc=_presence_check(ms, "dmarc"),
        dkim=_dkim_check(ms),
        results=results,
    )