from enum import StrEnum

class SourceStatus(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = " UNKNOWN"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    SOURCE_ERROR = "SOURCE_ERROR"

    @property
    def is_failure(self) -> bool:
        return self in {
            SourceStatus.TIMEOUT,
            SourceStatus.RATE_LIMITED,
            SourceStatus.AUTH_REQUIRED,
            SourceStatus.SOURCE_ERROR,
        }