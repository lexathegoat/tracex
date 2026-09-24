from __future__ import annotations

import ipaddress
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from tracex.utils import validation as v


class TargetType(StrEnum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"


class Target(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: TargetType
    value: str

    @property
    def domain(self) -> str | None:
        """Domain part for email/domain targets, else None."""
        if self.type is TargetType.DOMAIN:
            return self.value
        if self.type is TargetType.EMAIL:
            return self.value.rpartition("@")[2]
        return None

    @classmethod
    def parse(cls, type_: TargetType, raw: str) -> Target:
        """Validate and normalize raw user input. Raises ValueError if invalid."""
        raw = raw.strip()
        match type_:
            case TargetType.EMAIL:
                parts = v.split_email(raw)
                if parts is None:
                    raise ValueError("Invalid email address.")
                return cls(type=type_, value=f"{parts[0]}@{parts[1]}")
            case TargetType.DOMAIN:
                domain = v.normalize_domain(raw)
                if domain is None:
                    raise ValueError("Invalid domain name.")
                return cls(type=type_, value=domain)
            case TargetType.IP:
                try:
                    return cls(type=type_, value=str(ipaddress.ip_address(raw)))
                except ValueError as exc:
                    raise ValueError("Invalid IP address.") from exc
            case TargetType.USERNAME:
                name = v.normalize_username(raw)
                if name is None:
                    raise ValueError("Invalid username (1-64 chars: letters, digits, _ . -).")
                return cls(type=type_, value=name)
        raise ValueError(f"Unsupported target type: {type_}")

    @classmethod
    def detect(cls, raw: str) -> Target:
        """Guess the target type (used by `tracex investigate`)."""
        raw = raw.strip()
        if "@" in raw and not raw.startswith("@"):
            return cls.parse(TargetType.EMAIL, raw)
        try:
            ipaddress.ip_address(raw)
            return cls.parse(TargetType.IP, raw)
        except ValueError:
            pass
        if v.normalize_domain(raw) is not None:
            return cls.parse(TargetType.DOMAIN, raw)
        return cls.parse(TargetType.USERNAME, raw)