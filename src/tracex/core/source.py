from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar

from tracex.core.errors import SourceError
from tracex.core.result import SourceResult
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

if TYPE_CHECKING:
    from tracex.storage.cache import Cache

log = logging.getLogger(__name__)


class SourceAdapter(ABC):
    name: ClassVar[str]
    supported_targets: ClassVar[frozenset[TargetType]]

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.supported_targets

    @abstractmethod
    async def query(self, target: Target) -> Any:
        
    @abstractmethod
    def normalize(self, target: Target, raw: Any) -> SourceResult:
    async def health_check(self) -> bool:
        return True

    def _cache_key(self, target: Target) -> str:
        return f"{self.name}:{target.type.value}:{target.value}"

    async def run(
        self,
        target: Target,
        timeout: float = 10.0,
        cache: "Cache | None" = None,
    ) -> SourceResult:
        started = time.perf_counter()
        cache_key = self._cache_key(target)

        if cache is not None:
            cached = await cache.get(cache_key)
            if cached is not None:
                result = SourceResult.model_validate_json(cached)
                result.cached = True
                result.elapsed_ms = int((time.perf_counter() - started) * 1000)
                return result

        log.info("Querying source: %s", self.name)
        try:
            raw = await asyncio.wait_for(self.query(target), timeout=timeout)
            result = self.normalize(target, raw)
        except SourceError as exc:
            result = self._failure(target, exc.status, exc.message)
        except TimeoutError:
            result = self._failure(target, SourceStatus.TIMEOUT, f"no response within {timeout}s")
        except Exception as exc:  # noqa: BLE001 - adapters must never crash the engine
            log.debug("Source %s crashed", self.name, exc_info=True)
            result = self._failure(target, SourceStatus.SOURCE_ERROR, f"{type(exc).__name__}: {exc}")

        result.elapsed_ms = int((time.perf_counter() - started) * 1000)

        if result.status.is_failure:
            log.warning("Source %s: %s", self.name, result.status.value)
        elif cache is not None and result.status is SourceStatus.FOUND:
            await cache.set(cache_key, result.model_dump_json(), cache.ttl_for(self.name))

        return result

    def _failure(self, target: Target, status: SourceStatus, message: str) -> SourceResult:
        return SourceResult(source=self.name, target=target, status=status, error=message)
