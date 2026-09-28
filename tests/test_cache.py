import tempfile
from pathlib import Path

import pytest

from tracex.storage.cache import Cache


@pytest.fixture
def cache(tmp_path: Path) -> Cache:
    return Cache(path=tmp_path / "test.sqlite3")


async def test_set_and_get_roundtrip(cache: Cache):
    await cache.set("key1", '{"x": 1}', ttl_seconds=60)
    assert await cache.get("key1") == '{"x": 1}'


async def test_missing_key_returns_none(cache: Cache):
    assert await cache.get("nope") is None


async def test_expired_entry_returns_none(cache: Cache):
    await cache.set("key1", "value", ttl_seconds=-1)  # already expired
    assert await cache.get("key1") is None


async def test_overwrite_updates_value(cache: Cache):
    await cache.set("key1", "old", ttl_seconds=60)
    await cache.set("key1", "new", ttl_seconds=60)
    assert await cache.get("key1") == "new"


async def test_clear_removes_everything(cache: Cache):
    await cache.set("key1", "value", ttl_seconds=60)
    await cache.clear()
    assert await cache.get("key1") is None


def test_ttl_for_known_and_unknown_source(cache: Cache):
    assert cache.ttl_for("dns") == 300
    assert cache.ttl_for("totally_unknown_source") == 300  # fallback