from __future__ import annotations

import asyncio
from typing import Any

from tracex.analysis.mailsec import find_dmarc, find_spf
from tracex.core.confidence import Confidence
from tracex.core.errors import NXDomainError, SourceError
from tracex.core.finding import Finding
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim",
)


class MailSecSource(SourceAdapter):
    name = "mailsec"
    supported_targets = frozenset({TargetType.DOMAIN, TargetType.EMAIL})

    def __init__(self, client, selectors: tuple[str, ...] = COMMON_DKIM_SELECTORS) -> None:
        self._client = client
        self._selectors = selectors

    async def query(self, target: Target) -> dict[str, Any]:
        domain = target.domain
        assert domain is not None
        raw: dict[str, Any] = {
            "domain": domain, "nxdomain": False,
            "spf": None, "dmarc": None, "dkim_selectors": [],
        }
        try:
            txt = await self._client.lookup(domain, "TXT")
        except NXDomainError:
            raw["nxdomain"] = True
            return raw
        raw["spf"] = find_spf(txt)

        try:
            dmarc_txt = await self._client.lookup(f"_dmarc.{domain}", "TXT")
        except NXDomainError:
            dmarc_txt = []
        raw["dmarc"] = find_dmarc(dmarc_txt)

        hits = await asyncio.gather(*(self._probe_dkim(domain, s) for s in self._selectors))
        raw["dkim_selectors"] = [s for s, ok in zip(self._selectors, hits) if ok]
        return raw

    async def _probe_dkim(self, domain: str, selector: str) -> bool:
        try:
            txt = await self._client.lookup(f"{selector}._domainkey.{domain}", "TXT")
        except (NXDomainError, SourceError):
            return False
        return any("p=" in record.lower() for record in txt)

    def normalize(self, target: Target, raw: dict[str, Any]) -> SourceResult:
        if raw["nxdomain"]:
            return SourceResult(
                source=self.name, target=target, status=SourceStatus.NOT_FOUND,
                error="NXDOMAIN", data=raw,
            )
        findings: list[Finding] = []
        s = self.name

        if raw["spf"]:
            findings.append(Finding(
                title="SPF record detected", detail=raw["spf"], source=s,
                source_confidence=Confidence.HIGH,
            ))
        else:
            findings.append(Finding(
                title="No SPF record found", source=s, status=SourceStatus.NOT_FOUND,
                source_confidence=Confidence.HIGH,
            ))

        if raw["dmarc"]:
            policy = raw["dmarc"]["policy"] or "unspecified"
            findings.append(Finding(
                title="DMARC record detected", detail=f"policy={policy}", source=s,
                source_confidence=Confidence.HIGH, data=raw["dmarc"],
            ))
        else:
            findings.append(Finding(
                title="No DMARC record found", source=s, status=SourceStatus.NOT_FOUND,
                source_confidence=Confidence.HIGH,
            ))

        if raw["dkim_selectors"]:
            findings.append(Finding(
                title="DKIM key detected", detail=", ".join(raw["dkim_selectors"]), source=s,
                source_confidence=Confidence.HIGH,
            ))
        else:
            findings.append(Finding(
                title="DKIM could not be verified",
                detail="Selector is not publicly discoverable; only common selectors were probed.",
                source=s, status=SourceStatus.UNKNOWN, source_confidence=Confidence.LOW,
            ))

        found_any = bool(raw["spf"] or raw["dmarc"] or raw["dkim_selectors"])
        return SourceResult(
            source=s, target=target,
            status=SourceStatus.FOUND if found_any else SourceStatus.NOT_FOUND,
            findings=findings, data=raw,
        )