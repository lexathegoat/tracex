from __future__ import annotations

from tracex.core.status import SourceStatus


class SourceError(Exception):
    def __init__(self, status: SourceStatus, message: str = "") -> None:
        self.status = status
        self.message = message or status.value
        super().__init__(self.message)


class NXDomainError(Exception):