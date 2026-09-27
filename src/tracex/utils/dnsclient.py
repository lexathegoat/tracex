from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from tracex.core.errors import NXDomainError, SourceError
from tracex.core.status import SourceStatus

def _format(rdata, rtype: str) -> str:
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype in ("NS", "CNAME"):
        return rdata.target.to_tesxt().rstrip(".")
    return rdata.to_text()

class DnsClient:
    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    async def lookup(self, name: str, rtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as exc:
            raise NXDomainError(name) from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.Timeout as exc:
            raise SourceError(SourceStatus.TIMEOUT, f"DNS timeout ({rtype})") from exc
        except dns.resolver.NoNameservers as exc:
            raise SourceError(SourceStatus.SOURCE_ERROR, f"DNS SERVFAIL ({rtype})") from exc
        return [_format(rdata, rtype) for rdata in answer]

class DnsClient:
    async def reverse_lookup(self, ip: str) -> list[str]:
        name = dns.reversename.from_address(ip).to_text()
        return await self.lookup(name, "PTR")