"""Central secret redaction for persisted scan artifacts and diagnostics."""

from __future__ import annotations

import copy
import re
from typing import Any


REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|pass(?:word|wd)?|private[_-]?key|"
    r"proxy[_-]?authorization|secret|session|token)",
    re.IGNORECASE,
)
_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
            r"x-api-key)\s*:\s*)[^\r\n]+"
        ),
        rf"\1{REDACTED}",
    ),
    (
        re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
        rf"\1 {REDACTED}",
    ),
    (
        re.compile(
            r"(?i)([\"'](?:api[_-]?key|authorization|cookie|password|passwd|secret|"
            r"session|token)[\"']\s*:\s*)"
            r"(?:[\"'][^\"']*[\"']|[^,}\]\s]+)"
        ),
        rf"\1\"{REDACTED}\"",
    ),
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD)"
            r"[A-Z0-9_]*)\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
        ),
        rf"\1={REDACTED}",
    ),
    (
        re.compile(r"(?i)\b((?:session|auth_token|access_token|refresh_token)=)[^;\s&]+"),
        rf"\1{REDACTED}",
    ),
    (
        re.compile(r"(?i)(\bcurl\b[^\r\n]*?\s-u\s+)([^\s:]+):[^\s]+"),
        rf"\1\2:{REDACTED}",
    ),
    (
        re.compile(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@"),
        rf"\1{REDACTED}@",
    ),
)


def redact_sensitive_text(value: Any) -> str:
    """Remove common credential forms from free-form command/output text."""
    redacted = str(value or "")
    for pattern, replacement in _TEXT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_sensitive_data(value: Any, *, parent_key: str = "") -> Any:
    """Return a deep, secret-safe copy of nested artifact data."""
    if _SENSITIVE_KEY.search(parent_key):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(key): redact_sensitive_data(item, parent_key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return copy.deepcopy(value)
