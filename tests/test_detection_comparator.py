"""Tests for response-differential security oracles."""

from __future__ import annotations

import json

from aegis.detection.comparator import (
    evaluate_function_authorization,
    evaluate_idor,
    evaluate_mass_assignment,
)


def _response(status: int, body: dict[str, object]) -> dict[str, object]:
    return {
        "status_code": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def test_idor_oracle_confirms_matching_protected_object() -> None:
    protected = _response(
        200,
        {
            "id": 101,
            "owner_id": "user-a",
            "email": "owner@example.test",
            "updated_at": "volatile",
        },
    )
    negative = _response(404, {"error": "not found"})
    anonymous = _response(401, {"error": "unauthorized"})

    signal = evaluate_idor(protected, protected, negative, anonymous)

    assert signal.confirmed is True
    assert signal.classification == "confirmed_horizontal_idor"
    assert signal.confidence >= 0.9
    assert "owner_id" in signal.metrics["owner_vs_attacker"]["sensitive_field_matches"]


def test_idor_oracle_rejects_authorization_denial() -> None:
    owner = _response(200, {"id": 101, "owner_id": "user-a"})
    denied = _response(403, {"error": "forbidden"})

    signal = evaluate_idor(owner, denied, denied, denied)

    assert signal.confirmed is False
    assert signal.classification == "idor_not_confirmed"


def test_idor_oracle_rejects_public_resources() -> None:
    public = _response(200, {"id": 101, "owner_id": "user-a"})
    negative = _response(404, {"error": "not found"})

    signal = evaluate_idor(public, public, negative, public)

    assert signal.confirmed is False


def test_function_authorization_requires_anonymous_denial() -> None:
    protected = _response(200, {"id": 1, "email": "admin@example.test", "role": "admin"})
    anonymous = _response(401, {"error": "unauthorized"})

    confirmed = evaluate_function_authorization(protected, protected, anonymous)
    public = evaluate_function_authorization(protected, protected, protected)

    assert confirmed.confirmed is True
    assert public.confirmed is False


def test_mass_assignment_requires_reflection_and_controls() -> None:
    baseline = _response(200, {"id": 1, "role": "user"})
    mutated = _response(200, {"id": 1, "role": "admin"})
    control = _response(422, {"error": "unknown field"})
    anonymous = _response(401, {"error": "unauthorized"})

    signal = evaluate_mass_assignment(
        baseline,
        mutated,
        control,
        anonymous,
        field_name="role",
        mutation_value="admin",
    )

    assert signal.confirmed is True
    assert signal.classification == "confirmed_mass_assignment"
