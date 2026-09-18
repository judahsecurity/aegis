"""Tests for deterministic attack-surface extraction."""

from __future__ import annotations

from aegis.detection.extractor import (
    auth_headers,
    extract_parameters,
    template_path,
    workflow_hints,
)


def test_route_template_recognizes_common_identifier_shapes() -> None:
    route, parameters = template_path(
        "/api/accounts/123/documents/550e8400-e29b-41d4-a716-446655440000"
    )

    assert route == "/api/accounts/{integer}/documents/{uuid}"
    assert [parameter.value_kind for parameter in parameters] == ["integer", "uuid"]
    assert all(parameter.identifier_score >= 0.65 for parameter in parameters)


def test_extractor_finds_query_and_nested_json_identifiers() -> None:
    parameters = extract_parameters(
        "/api/search?account_id=42&q=hello",
        '{"order":{"owner_id":"user-123"},"description":"test"}',
        "application/json",
    )
    by_name = {parameter.name: parameter for parameter in parameters}

    assert by_name["account_id"].location == "query"
    assert by_name["account_id"].identifier_score >= 0.65
    assert by_name["order.owner_id"].location == "body"
    assert by_name["order.owner_id"].identifier_score >= 0.65
    assert by_name["q"].identifier_score < 0.65
    assert by_name["q"].sample_value == ""


def test_extractor_does_not_persist_secret_values() -> None:
    parameters = extract_parameters(
        "/api/session",
        '{"password":"correct-horse","access_token":"sensitive-token"}',
        "application/json",
    )

    assert {parameter.sample_value for parameter in parameters} == {""}
    assert {parameter.identifier_score for parameter in parameters} == {0.0}


def test_extractor_marks_privileged_fields_and_auth_workflows() -> None:
    parameters = extract_parameters(
        "/api/register",
        '{"email":"user@example.test","role":"user","isAdmin":false}',
        "application/json",
    )
    by_name = {parameter.name: parameter for parameter in parameters}

    assert by_name["role"].mutation_score >= 0.65
    assert by_name["isAdmin"].mutation_score >= 0.65
    assert "authentication_flow" in workflow_hints("POST", "/api/register", parameters)
    assert "state_changing" in workflow_hints("POST", "/api/register", parameters)


def test_auth_headers_support_custom_auth_without_treating_csrf_as_identity() -> None:
    extracted = auth_headers(
        {
            "X-Custom-Auth-Token": "secret",
            "X-CSRF-Token": "rotating",
            "User-Agent": "test",
        }
    )

    assert extracted == {"X-Custom-Auth-Token": "secret"}
