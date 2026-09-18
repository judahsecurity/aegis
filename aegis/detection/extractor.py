"""Deterministic extraction of routes and security-relevant parameters."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from aegis.detection.models import ParameterCandidate


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_INTEGER_RE = re.compile(r"^-?\d+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{12,}$")
_IDENTIFIER_NAME_RE = re.compile(
    r"(^id$|_id$|^id_|uuid|guid|owner|account|user|tenant|organi[sz]ation|"
    r"order|invoice|document|record|project|team|customer|profile)",
    re.IGNORECASE,
)
_SECRET_NAME_RE = re.compile(
    r"password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"authorization|cookie|csrf|xsrf",
    re.IGNORECASE,
)
_PRIVILEGED_FIELD_RE = re.compile(
    r"(^|[_.-])(role|roles|admin|is[_-]?admin|permission|permissions|privilege|"
    r"verified|approved|owner[_-]?id|user[_-]?id|account[_-]?id|tenant[_-]?id|"
    r"organization[_-]?id|status|balance|credit|price)($|[_.-])",
    re.IGNORECASE,
)
_AUTH_FLOW_RE = re.compile(
    r"(^|/)(login|signin|sign-in|authenticate|auth|token|session|register|signup|"
    r"sign-up|logout|signout|password|reset|forgot|refresh)(/|$)",
    re.IGNORECASE,
)
_ADMIN_ROUTE_RE = re.compile(
    r"(^|/)(admin|administrator|manage|management|staff|internal|superuser)(/|$)",
    re.IGNORECASE,
)
_AUTH_HEADER_NAMES = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}
_CUSTOM_AUTH_HEADER_RE = re.compile(
    r"^x-[a-z0-9-]*(auth|token|api-key|session|user-id|account-id)[a-z0-9-]*$",
    re.IGNORECASE,
)


def classify_value(value: str) -> str:
    candidate = str(value or "")
    if _UUID_RE.fullmatch(candidate):
        return "uuid"
    if _INTEGER_RE.fullmatch(candidate):
        return "integer"
    if _HEX_RE.fullmatch(candidate):
        return "hex"
    if _TOKEN_RE.fullmatch(candidate):
        return "token"
    return "string"


def identifier_score(name: str, value: str, *, location: str) -> float:
    if _SECRET_NAME_RE.search(name):
        return 0.0
    score = 0.15
    if _IDENTIFIER_NAME_RE.search(name):
        score += 0.55
    value_kind = classify_value(value)
    if value_kind in {"uuid", "integer", "hex", "token"}:
        score += 0.2
    if location == "path":
        score += 0.3
    return round(min(score, 1.0), 3)


def mutation_score(name: str) -> float:
    """Score fields commonly trusted by unsafe object binding."""
    if _SECRET_NAME_RE.search(name):
        return 0.0
    if _PRIVILEGED_FIELD_RE.search(name):
        return 0.9
    return 0.0


def workflow_hints(method: str, url_path: str, parameters: list[ParameterCandidate]) -> list[str]:
    """Classify captured endpoints without retaining request secrets."""
    path = urlsplit(url_path).path
    hints: set[str] = set()
    if _AUTH_FLOW_RE.search(path):
        hints.add("authentication_flow")
    if _ADMIN_ROUTE_RE.search(path):
        hints.add("privileged_route")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        hints.add("state_changing")
    if any(parameter.identifier_score >= 0.65 for parameter in parameters):
        hints.add("object_reference")
    if any(parameter.mutation_score >= 0.65 for parameter in parameters):
        hints.add("privileged_field")
    return sorted(hints)


def template_path(path: str) -> tuple[str, list[ParameterCandidate]]:
    """Canonicalize likely object identifiers in path segments."""
    segments = (urlsplit(path).path or "/").split("/")
    parameters: list[ParameterCandidate] = []
    rendered: list[str] = []
    for index, segment in enumerate(segments):
        kind = classify_value(segment)
        if segment and kind in {"uuid", "integer", "hex", "token"}:
            name = f"path_segment_{index}"
            parameters.append(
                ParameterCandidate(
                    name=name,
                    location="path",
                    sample_value=segment,
                    value_kind=kind,
                    identifier_score=identifier_score(name, segment, location="path"),
                    mutation_score=0.0,
                )
            )
            rendered.append(f"{{{kind}}}")
        else:
            rendered.append(segment)
    route = "/".join(rendered) or "/"
    return route if route.startswith("/") else f"/{route}", parameters


def _flatten_json(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    flattened: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            flattened.extend(_flatten_json(child, name))
    elif isinstance(value, list):
        for index, child in enumerate(value[:3]):
            flattened.extend(_flatten_json(child, f"{prefix}[{index}]"))
    elif value is not None:
        flattened.append((prefix, str(value)))
    return flattened


def extract_parameters(url_path: str, body: str, content_type: str) -> list[ParameterCandidate]:
    """Extract path, query, JSON, and form parameters."""
    parsed = urlsplit(url_path)
    _, parameters = template_path(parsed.path)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        score = identifier_score(name, value, location="query")
        parameters.append(
            ParameterCandidate(
                name=name,
                location="query",
                sample_value=value if score >= 0.65 else "",
                value_kind=classify_value(value),
                identifier_score=score,
                mutation_score=mutation_score(name),
            )
        )

    body_values: list[tuple[str, str]] = []
    if body and "json" in content_type.lower():
        try:
            body_values = _flatten_json(json.loads(body))
        except json.JSONDecodeError:
            body_values = []
    elif body and "application/x-www-form-urlencoded" in content_type.lower():
        body_values = [(name, value) for name, value in parse_qsl(body, keep_blank_values=True)]

    for name, value in body_values:
        score = identifier_score(name, value, location="body")
        field_mutation_score = mutation_score(name)
        parameters.append(
            ParameterCandidate(
                name=name,
                location="body",
                sample_value=value if score >= 0.65 or field_mutation_score >= 0.65 else "",
                value_kind=classify_value(value),
                identifier_score=score,
                mutation_score=field_mutation_score,
            )
        )
    return parameters


def auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return authentication/session headers without logging their values."""
    return {
        key: value
        for key, value in headers.items()
        if "csrf" not in key.lower()
        and "xsrf" not in key.lower()
        and (key.lower() in _AUTH_HEADER_NAMES or _CUSTOM_AUTH_HEADER_RE.fullmatch(key.lower()))
    }


def content_type(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value
    return ""
