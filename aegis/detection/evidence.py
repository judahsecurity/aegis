"""Deterministic evidence grading for reported authorization findings.

This module deliberately does not use status codes as a vulnerability oracle.
A successful status can be normal application behavior; promotion requires a
protected-object observation and an independently described control.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal
from urllib.parse import urlsplit


EvidenceLevel = Literal["verified", "likely_vulnerable", "insufficient"]

_POSITIVE_TERMS = (
    "another user",
    "cross-user",
    "different user",
    "non-owner",
    "not owned",
    "other user",
    "owned by a different",
    "protected object",
    "private data",
    "sensitive data",
    "unauthorized access",
)
_CONTROL_TERMS = (
    "anonymous control",
    "baseline",
    "control request",
    "negative control",
    "nonexistent",
    "not found control",
    "owner control",
    "same request without",
    "without a session",
    "without authentication",
)
_AUTH_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    """Secret-free summary of an HTTP evidence set."""

    level: EvidenceLevel
    complete_exchanges: int
    protected_observations: int
    controls: int
    distinct_auth_contexts: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _description(entry: dict[str, Any]) -> str:
    return " ".join(str(entry.get("description") or "").lower().split())


def _has_term(value: str, terms: tuple[str, ...]) -> bool:
    return any(term in value for term in terms)


def _auth_fingerprint(entry: dict[str, Any]) -> str:
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    material = "\x1f".join(
        f"{str(key).lower()}={value}"
        for key, value in sorted(headers.items(), key=lambda item: str(item[0]).lower())
        if str(key).lower() in _AUTH_HEADER_NAMES
    )
    if not material:
        return "anonymous"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def normalize_route(value: str) -> str:
    """Normalize concrete and named-placeholder paths for evidence matching."""
    parsed = urlsplit(str(value or "").strip())
    path = parsed.path or "/"
    path = re.sub(r"\{[^/{}]+\}", "{param}", path)
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{param}", path)
    path = re.sub(
        r"(?<=/)[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)",
        "{param}",
        path,
        flags=re.IGNORECASE,
    )
    return path.rstrip("/").lower() or "/"


def assess_http_evidence(  # noqa: PLR0912 - explicit evidence gates are intentional.
    entries: list[dict[str, Any]] | None,
) -> EvidenceAssessment:
    """Grade paired HTTP evidence without accepting an HTTP status as proof."""
    complete: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []

    for raw in entries or []:
        if not isinstance(raw, dict):
            continue
        request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        response = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        method = str(request.get("method") or "").strip().upper()
        url = str(request.get("url") or "").strip()
        if not method or not url or not isinstance(response.get("status_code"), int):
            continue
        complete.append(raw)
        description = _description(raw)
        response_body = str(response.get("body") or "").strip()
        if response_body and _has_term(description, _POSITIVE_TERMS):
            protected.append(raw)
        if _has_term(description, _CONTROL_TERMS):
            controls.append(raw)

    auth_contexts = {_auth_fingerprint(entry) for entry in complete}
    reasons: list[str] = []
    if len(complete) < 2:
        reasons.append("fewer than two complete HTTP exchanges")
    if not protected:
        reasons.append("no response body is described as exposing another principal's object")
    if not controls:
        reasons.append("no independently described baseline or negative control")
    if len(auth_contexts) < 2:
        reasons.append("evidence does not contain distinct authentication contexts")

    # The positive and control must exercise the same method and normalized
    # route family. This prevents unrelated recent proxy traffic from acting as
    # the control for a finding.
    paired = False
    for positive in protected:
        positive_request = positive["request"]
        positive_key = (
            str(positive_request.get("method") or "").upper(),
            normalize_route(str(positive_request.get("url") or "")),
        )
        for control in controls:
            control_request = control["request"]
            control_key = (
                str(control_request.get("method") or "").upper(),
                normalize_route(str(control_request.get("url") or "")),
            )
            if positive_key == control_key:
                paired = True
                break
        if paired:
            break
    if protected and controls and not paired:
        reasons.append("positive observation and control do not target the same route")

    if protected and controls and paired and len(auth_contexts) >= 2:
        level: EvidenceLevel = "verified"
        reasons = [
            "protected-object response is paired with a same-route control",
            "the pair uses distinct authentication contexts",
        ]
    elif len(complete) >= 2 and controls:
        level = "likely_vulnerable"
    else:
        level = "insufficient"

    return EvidenceAssessment(
        level=level,
        complete_exchanges=len(complete),
        protected_observations=len(protected),
        controls=len(controls),
        distinct_auth_contexts=len(auth_contexts),
        reasons=tuple(reasons),
    )
