from __future__ import annotations

import asyncio 
import logging
from collections.abc import Sequence

from tracex.core.result import SourceResult
from tracex.core.source import SourceAdapter
from tracex.core.target import Target

log = logging.getLogger(__name__)

async def run_sources(
        target: Target,
        adapters: Sequence[SourceAdapter],
        timeout: float = 10.0,
) -> list[SourceResult]:
    eligible = [a for a in adapters if a.supports(target.type)]
    log.info("running %d source(s) for %s target", len(eligible), target.type.value)
    return list(await asyncio.gather(*(a.run(target, timeout) for a in eligible)))