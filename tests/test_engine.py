import asyncio

from tracex.core.engine import run_sources
from tracex.core.errors import SourceError
from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

TARGET = Target.parse(TargetType.DOMAIN, "example.com")
SUPPORTED = frozenset({TargetType.DOMAIN})

class _Base(SourceAdapter):
    supported_targets = SUPPORTED

    def normalize(self, target, raw):
        return SourceResult(source=self.name, target=target, status=SourceStatus.FOUND, data=raw)

class Ok(_Base):
    name = "ok"

    async def query(self, target):
        return {"x": 1}

class Slow(_Base):
    name = "slow"

    async def query(self, target):
        await asyncio.sleep(1)

class Boom(_Base):
    name = "boom"

    async def query(self, target):
        raise RuntimeError("kaboom")

class Limited(_Base):
    name = "limited"

    async def query(self, target):
        raise SourceError(SourceStatus.RATE_LIMITED, "slow down")

class WrongType(_Base):
    name = "wrong"
    supported_targets = frozenset({TargetType.IP})

    async def query(self, target):
        return {}

async def test_status_are_distinguished():
    results = await run_sources(TARGET, [Ok(), Slow(), Boom(), Limited()], timeout=0.05)
    by_name = {r.source: r.status for r in results}
    assert by_name == {
        "ok": SourceStatus.FOUND,
        "slow": SourceStatus.TIMEOUT,
        "boom": SourceStatus.SOURCE_ERROR,
        "limited": SourceStatus.RATE_LIMITED,
    }

async def test_unsupported_sources_are_skipped():
    results = await run_sources(TARGET, [Ok(), WrongType()])
    assert [r.source for r in results] == ["ok"]