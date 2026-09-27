from __future__ import annotations

from tracex.core.status import SourceStatus


class SourceError(Exception):
    """Raised by adapters to signal a specific non-success status."""

    def __init__(self, status: SourceStatus, message: str = "") -> None:
        self.status = status
        self.message = message or status.value
        super().__init__(self.message)


class NXDomainError(Exception):
    """The queried DNS name does not exist (authoritative NXDOMAIN)."""