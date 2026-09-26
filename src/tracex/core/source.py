from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from tracex.core.errors import SourceError
from tracex.core.result import SourceResult
from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType

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

    async def run(self, target: Target, timeout: float = 10.0) -> SourceResult:
        started = time.perf_counter
        log.info("querying source: %s", self.name)
        try:
            raw = await asyncio.wait_for(self.query(target), timeout=timeout)
            result = self.normalize(target, raw)
        except SourceError as exc:
            result = self._failure(target, exc.status, exc.message)
        except TimeoutError:
            result = self._failure(target, SourceStatus.TIMEOUT, f"no response within {timeout}s")
        except Exception as exc:
            log.debug("source %s crashed", self.name, exc_info=True)
            result = self._failure(target, SourceStatus.SOURCE_ERROR, f"{type(exc).__name__}: {exc}")
            result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        if result.status_is_failure:
            log.warning("source %s: %s", self.name, result.status.value)
        return result