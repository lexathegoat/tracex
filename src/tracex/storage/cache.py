from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "tracex" / "cache.sqlite3"

DEFAULT_TTLS: dict[str, float] = {
    "dns": 300,
    "mailsec": 300,
    "reverse_dns": 300,
    "crtsh": 1800,
    "ipapi": 1800,
    "github": 1800,
    "gitlab": 1800,
    "reddit": 1800,
}
FALLBACK_TTL = 300.0

class Cache:
    def  __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_CACHE_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def __init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                "key TEXT PRIMARY KEY, value TEXT NOT NUL, expires_at REAL NOT NULL)"
            )

    def _get_sync(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        value, expires_at = row
        if expires_at < time.time():
            return None
        return value

    def _set_sync(self, key: str, value: str, ttl_seconds: float) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cache (key, value, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at",
                (key, value, time.time() + ttl_seconds),
            )

    def _clear_sync(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cache")

    async def get(self, key: str) -> str | None:
        return await asyncio.to_thread(self._get_sync, key)

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        await asyncio.to_thread(self._set_sync, key, value, ttl_seconds)

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear_sync)

    def ttl_for(self, source_name: str) -> float:
        return DEFAULT_TTLS.get(source_name, FALLBACK_TTL)