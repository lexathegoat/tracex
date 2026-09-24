from __future__ import annotations

import re

_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_USERNAME_RE = re.compile(r"^[\w.-]{1,64}$")

def normalize_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value:
        return None
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    if labels[-1].isdigit(): # 1.2.3.4 is an IP not a domain
        return None
    return ascii_name

def is_valid_local_part(local: str) -> bool:
    return (
        0 < len(local) <= 64
        and bool(_LOCAL_RE.match(local))
        and not local.startswith(".")
        and not local.endswith(".")
        and ".." not in local
    )

def split_email(value: str) -> tuple[str, str] | None:
    local, sep, domain = value.strip().rpartition("@")
    if not sep or not is_valid_local_part(local):
        return None
    normalized = normalize_domain(domain)
    if normalized is None:
        return None
    return local.lower(), normalized

def normalize_username(value: str) -> str | None:
    value = value.strip().removeprefix("@")
    return value if _USERNAME_RE.match(value) else None