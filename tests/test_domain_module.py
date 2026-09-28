from tracex.core.errors import NXDomainError
from tracex.core.target import Target, TargetType
from tracex.modules.domain import analyze_domain
from tracex.sources.ct import CrtShSource

TARGET = Target.parse(TargetType.DOMAIN, "example.com")


class FakeDns:
    def __init__(self, table, nxdomain=()):
        self.table = table
        self.nxdomain = set(nxdomain)

    async def lookup(self, name, rtype):
        if name in self.nxdomain:
            raise NXDomainError(name)
        return self.table.get((name, rtype), [])


class FakeCrtSh(CrtShSource):
    def __init__(self, hostnames):
        super().__init__()
        self._hostnames = hostnames

    async def query(self, target):
        return [{"name_value": h} for h in self._hostnames]


async def test_domain_report_shape(monkeypatch):
    dns = FakeDns({("example.com", "A"): ["1.2.3.4"]})

    async def fake_run_sources(target, adapters, timeout=10.0, cache=None):
        from tracex.sources.dns import DnsSource
        from tracex.sources.mailsec import MailSecSource
        results = []
        for a in adapters:
            if isinstance(a, (DnsSource, MailSecSource)):
                results.append(await a.run(target, timeout))
            else:
                a._client = None
                a.query = FakeCrtSh(["api.example.com"]).query
                results.append(await a.run(target, timeout))
        return results

    import tracex.modules.domain as domain_mod
    monkeypatch.setattr(domain_mod, "run_sources", fake_run_sources)

    report = await analyze_domain(TARGET, dns_client=dns)
    payload = report.to_payload()
    assert set(payload) == {"target", "checks", "subdomains", "findings", "entities", "sources", "timestamp"}
    assert "api.example.com" in report.subdomains