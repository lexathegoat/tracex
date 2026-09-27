from __future__ import annotations

from typing import Any


def find_spf(txt_records: list[str]) -> str | None:
    for record in txt_records:
        if record.strip().lower().startswith("v=spf1"):
            return record.strip()
    return None


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def find_dmarc(txt_records: list[str]) -> dict[str, Any] | None:
    for record in txt_records:
        if record.strip().lower().startswith("v=dmarc1"):
            tags = parse_dmarc(record)
            return {
                "record": record.strip(),
                "policy": tags.get("p"),
                "subdomain_policy": tags.get("sp"),
                "pct": tags.get("pct"),
                "rua": tags.get("rua"),
            }
    return None