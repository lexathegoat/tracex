from tracex.core.errors import NXDomainError
from tracex.core.target import Target, TargetType
from tracex.modules.email import Check, analyze_email


class FakeDns:
    def __init__(self, table, nxdomain=()):
        self.table = table
        self.nxdomain = set(nxdomain)

    async def lookup(self, name, rtype):
        if name in self.nxdomain:
            raise NXDomainError(name)
        return self.table.get((name, rtype), [])


TARGET = Target.parse(TargetType.EMAIL, "test@example.com")


async def test_full_setup():
    dns = FakeDns({
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "MX"): ["10 mail.example.com"],
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
        ("selector1._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf"],
    })
    report = await analyze_email(TARGET, dns_client=dns)
    assert (report.domain, report.mx, report.spf, report.dmarc, report.dkim) == (Check.OK,) * 5
    assert any(e.value == "mail.example.com" for r in report.results for e in r.entities)


async def test_missing_records_and_unknown_dkim():
    dns = FakeDns({("example.com", "A"): ["1.2.3.4"]})
    report = await analyze_email(TARGET, dns_client=dns)
    assert report.spf is Check.FAIL
    assert report.dmarc is Check.FAIL
    assert report.dkim is Check.UNKNOWN   # not found != absent
    assert report.mx is Check.UNKNOWN     # implicit MX fallback possible


async def test_nxdomain():
    report = await analyze_email(TARGET, dns_client=FakeDns({}, nxdomain={"example.com"}))
    assert report.domain is Check.FAIL
    assert report.mx is Check.FAIL


async def test_json_payload_shape():
    report = await analyze_email(TARGET, dns_client=FakeDns({}))
    payload = report.to_payload()
    assert set(payload) == {"target", "checks", "findings", "entities", "sources", "timestamp"}