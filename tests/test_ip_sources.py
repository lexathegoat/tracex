from tracex.core.target import Target, TargetType
from tracex.sources.reverse_dns import ReverseDnsSource

TARGET = Target.parse(TargetType.IP, "8.8.8.8")


class FakeDns:
    def __init__(self, ptr):
        self._ptr = ptr

    async def reverse_lookup(self, ip):
        return self._ptr


async def test_reverse_dns_found():
    r = await ReverseDnsSource(FakeDns(["dns.google."])).run(TARGET)
    assert r.status.value == "FOUND"
    assert r.entities[0].value == "dns.google"


async def test_reverse_dns_not_found():
    r = await ReverseDnsSource(FakeDns([])).run(TARGET)
    assert r.status.value == "NOT_FOUND"