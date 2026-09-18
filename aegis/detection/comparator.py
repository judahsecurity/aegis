"""Semantic HTTP response comparison and authorization-bypass oracles."""

from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from typing import Any

from aegis.detection.models import DetectionSignal


_VOLATILE_KEY_RE = re.compile(
    r"(^|_)(timestamp|time|date|nonce|csrf|xsrf|token|trace|request_id|requestid|etag|"
    r"created_at|updated_at|expires_at)($|_)",
    re.IGNORECASE,
)
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(id|owner|user|account|tenant|email|address|phone|ssn|secret|balance)($|_)",
    re.IGNORECASE,
)


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _normalize_json(child)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
            if not _VOLATILE_KEY_RE.search(str(key))
        }
    if isinstance(value, list):
        return [_normalize_json(child) for child in value]
    return value


def _body_value(response: dict[str, Any] | None) -> Any:
    if not response:
        return None
    body = response.get("body", "")
    if not isinstance(body, str):
        return body
    try:
        return _normalize_json(json.loads(body))
    except (json.JSONDecodeError, TypeError):
        return " ".join(body.split())


def _canonical_body(response: dict[str, Any] | None) -> str:
    value = _body_value(response)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(value or "")


def _json_paths(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.add(path)
            paths.update(_json_paths(child, path))
    elif isinstance(value, list):
        paths.add(f"{prefix}[]")
        for child in value[:3]:
            paths.update(_json_paths(child, f"{prefix}[]"))
    return paths


def _sensitive_values(value: Any, prefix: str = "") -> dict[str, str]:
    values: dict[str, str] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _SENSITIVE_KEY_RE.search(str(key)) and not isinstance(child, (dict, list)):
                values[path] = str(child)
            values.update(_sensitive_values(child, path))
    elif isinstance(value, list):
        for child in value[:3]:
            values.update(_sensitive_values(child, f"{prefix}[]"))
    return values


def compare_responses(
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return compact semantic similarity metrics for two HTTP responses."""
    left_body = _canonical_body(left)
    right_body = _canonical_body(right)
    body_similarity = SequenceMatcher(None, left_body, right_body).ratio()
    left_value = _body_value(left)
    right_value = _body_value(right)
    left_paths = _json_paths(left_value)
    right_paths = _json_paths(right_value)
    union = left_paths | right_paths
    shape_similarity = len(left_paths & right_paths) / len(union) if union else 1.0
    left_sensitive = _sensitive_values(left_value)
    right_sensitive = _sensitive_values(right_value)
    shared_keys = set(left_sensitive) & set(right_sensitive)
    sensitive_matches = sorted(
        key for key in shared_keys if left_sensitive[key] == right_sensitive[key]
    )
    status_equal = False
    if left is not None and right is not None:
        status_equal = left.get("status_code") == right.get("status_code")
    return {
        "left_status": left.get("status_code") if left else None,
        "right_status": right.get("status_code") if right else None,
        "status_equal": status_equal,
        "body_similarity": round(body_similarity, 4),
        "shape_similarity": round(shape_similarity, 4),
        "sensitive_field_matches": sensitive_matches,
    }


def evaluate_idor(
    owner: dict[str, Any] | None,
    attacker: dict[str, Any] | None,
    negative: dict[str, Any] | None,
    anonymous: dict[str, Any] | None = None,
) -> DetectionSignal:
    """Evaluate owner, attacker, anonymous, and nonexistent-object controls."""
    owner_attacker = compare_responses(owner, attacker)
    attacker_negative = compare_responses(attacker, negative)
    owner_anonymous = compare_responses(owner, anonymous)
    owner_status = owner_attacker["left_status"]
    attacker_status = owner_attacker["right_status"]
    negative_status = attacker_negative["right_status"]
    anonymous_status = owner_anonymous["right_status"]
    owner_ok = isinstance(owner_status, int) and 200 <= owner_status < 300
    attacker_ok = isinstance(attacker_status, int) and 200 <= attacker_status < 300
    negative_denied = isinstance(negative_status, int) and negative_status in {400, 401, 403, 404}
    strong_match = (
        owner_attacker["body_similarity"] >= 0.82 and owner_attacker["shape_similarity"] >= 0.8
    )
    negative_distinct = (
        negative_denied
        or owner_attacker["body_similarity"] - attacker_negative["body_similarity"] >= 0.25
    )
    anonymous_denied = anonymous is not None and (
        (isinstance(anonymous_status, int) and anonymous_status in {401, 403, 404})
        or (owner_attacker["body_similarity"] - owner_anonymous["body_similarity"] >= 0.25)
    )
    sensitive_match = bool(owner_attacker["sensitive_field_matches"])
    confirmed = bool(
        owner_ok
        and attacker_ok
        and strong_match
        and sensitive_match
        and negative_distinct
        and anonymous_denied
    )

    reasons: list[str] = []
    if owner_ok:
        reasons.append("Owner baseline returned a successful response")
    if attacker_ok:
        reasons.append("Alternate identity received a successful response")
    if strong_match:
        reasons.append("Owner and alternate-identity responses were semantically equivalent")
    if sensitive_match:
        reasons.append("Protected identity or object fields matched across identities")
    if negative_distinct:
        reasons.append("Negative control was denied or semantically distinct")
    if anonymous_denied:
        reasons.append("Anonymous control could not retrieve the protected object")

    confidence = 0.0
    confidence += 0.2 if owner_ok else 0.0
    confidence += 0.25 if attacker_ok else 0.0
    confidence += 0.2 if strong_match else 0.0
    confidence += 0.15 if sensitive_match else 0.0
    confidence += 0.1 if negative_distinct else 0.0
    confidence += 0.1 if anonymous_denied else 0.0
    classification = "confirmed_horizontal_idor" if confirmed else "idor_not_confirmed"
    return DetectionSignal(
        classification=classification,
        confidence=round(confidence, 3),
        confirmed=confirmed,
        reasons=reasons,
        metrics={
            "owner_vs_attacker": owner_attacker,
            "attacker_vs_negative": attacker_negative,
            "owner_vs_anonymous": owner_anonymous,
        },
    )


def evaluate_function_authorization(
    privileged: dict[str, Any] | None,
    lower_privileged: dict[str, Any] | None,
    anonymous: dict[str, Any] | None,
) -> DetectionSignal:
    """Evaluate vertical/function-level authorization with explicit controls."""
    role_comparison = compare_responses(privileged, lower_privileged)
    anonymous_comparison = compare_responses(privileged, anonymous)
    privileged_status = role_comparison["left_status"]
    lower_status = role_comparison["right_status"]
    anonymous_status = anonymous_comparison["right_status"]
    privileged_ok = isinstance(privileged_status, int) and 200 <= privileged_status < 300
    lower_ok = isinstance(lower_status, int) and 200 <= lower_status < 300
    semantic_match = (
        role_comparison["body_similarity"] >= 0.82 and role_comparison["shape_similarity"] >= 0.8
    )
    protected_data_match = bool(role_comparison["sensitive_field_matches"])
    anonymous_denied = anonymous is not None and (
        (isinstance(anonymous_status, int) and anonymous_status in {401, 403, 404})
        or anonymous_comparison["body_similarity"] <= 0.57
    )
    confirmed = bool(
        privileged_ok and lower_ok and semantic_match and protected_data_match and anonymous_denied
    )
    reasons: list[str] = []
    if privileged_ok:
        reasons.append("Privileged baseline succeeded")
    if lower_ok:
        reasons.append("Lower-privileged identity reached the privileged function")
    if semantic_match:
        reasons.append("Privileged and lower-privileged responses were semantically equivalent")
    if protected_data_match:
        reasons.append("Protected fields matched across roles")
    if anonymous_denied:
        reasons.append("Anonymous control was denied or semantically distinct")
    confidence = sum(
        (
            0.2 if privileged_ok else 0.0,
            0.25 if lower_ok else 0.0,
            0.2 if semantic_match else 0.0,
            0.2 if protected_data_match else 0.0,
            0.15 if anonymous_denied else 0.0,
        )
    )
    return DetectionSignal(
        classification=(
            "confirmed_broken_function_level_authorization"
            if confirmed
            else "function_authorization_not_confirmed"
        ),
        confidence=round(confidence, 3),
        confirmed=confirmed,
        reasons=reasons,
        metrics={
            "privileged_vs_lower_privileged": role_comparison,
            "privileged_vs_anonymous": anonymous_comparison,
        },
    )


def _json_field_matches(response: dict[str, Any] | None, field_name: str, expected: str) -> bool:
    value = _body_value(response)
    expected_normalized = expected.strip().lower()

    def visit(item: Any) -> bool:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() == field_name.lower():
                    child_value = str(child).strip().lower()
                    if child_value == expected_normalized:
                        return True
                if visit(child):
                    return True
        elif isinstance(item, list):
            return any(visit(child) for child in item[:10])
        return False

    return visit(value)


def evaluate_mass_assignment(
    baseline: dict[str, Any] | None,
    mutated: dict[str, Any] | None,
    unknown_field_control: dict[str, Any] | None,
    anonymous: dict[str, Any] | None,
    *,
    field_name: str,
    mutation_value: str,
) -> DetectionSignal:
    """Evaluate unsafe object binding using mutation, unknown-field, and auth controls."""
    baseline_mutated = compare_responses(baseline, mutated)
    baseline_control = compare_responses(baseline, unknown_field_control)
    baseline_anonymous = compare_responses(baseline, anonymous)
    baseline_status = baseline_mutated["left_status"]
    mutation_status = baseline_mutated["right_status"]
    anonymous_status = baseline_anonymous["right_status"]
    baseline_ok = isinstance(baseline_status, int) and 200 <= baseline_status < 300
    mutation_ok = isinstance(mutation_status, int) and 200 <= mutation_status < 300
    reflected = _json_field_matches(mutated, field_name, mutation_value)
    meaningful_change = baseline_mutated["body_similarity"] <= 0.92
    control_distinct = baseline_control["body_similarity"] >= baseline_mutated[
        "body_similarity"
    ] + 0.05 or baseline_control["right_status"] in {400, 422}
    anonymous_denied = anonymous is not None and (
        (isinstance(anonymous_status, int) and anonymous_status in {401, 403, 404})
        or baseline_anonymous["body_similarity"] <= 0.57
    )
    confirmed = bool(
        baseline_ok
        and mutation_ok
        and reflected
        and meaningful_change
        and control_distinct
        and anonymous_denied
    )
    reasons: list[str] = []
    if baseline_ok and mutation_ok:
        reasons.append("Baseline and privileged-field mutation both succeeded")
    if reflected:
        reasons.append("Response reflected the attacker-selected privileged value")
    if meaningful_change:
        reasons.append("Privileged mutation produced a meaningful response change")
    if control_distinct:
        reasons.append("Unknown-field control was rejected or behaved differently")
    if anonymous_denied:
        reasons.append("Anonymous mutation control was denied or semantically distinct")
    confidence = sum(
        (
            0.2 if baseline_ok else 0.0,
            0.2 if mutation_ok else 0.0,
            0.25 if reflected else 0.0,
            0.1 if meaningful_change else 0.0,
            0.1 if control_distinct else 0.0,
            0.15 if anonymous_denied else 0.0,
        )
    )
    return DetectionSignal(
        classification="confirmed_mass_assignment"
        if confirmed
        else "mass_assignment_not_confirmed",
        confidence=round(confidence, 3),
        confirmed=confirmed,
        reasons=reasons,
        metrics={
            "baseline_vs_mutated": baseline_mutated,
            "baseline_vs_unknown_field": baseline_control,
            "baseline_vs_anonymous": baseline_anonymous,
            "mutation_reflected": reflected,
        },
    )
