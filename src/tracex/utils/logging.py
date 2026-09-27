from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    handler = RichHandler(
        console=Console(stderr=True), show_path=False, show_time=False, markup=False
    )
    logging.basicConfig(level=level, handlers=[handler], format="%(message)s", force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)