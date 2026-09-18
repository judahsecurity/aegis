"""Tests for the agent-facing detection workflow tools."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool_context import ToolContext

from aegis.detection.store import DetectionStore
from aegis.detection.tools import (
    _apply_identity,
    generate_idor_hypotheses,
    inspect_detection_state,
    register_test_identity,
)
from aegis.tools.proxy import caido_api


def _capture(path: str, token: str, body: dict[str, object]) -> SimpleNamespace:
    request_raw = (
        f"GET {path} HTTP/1.1\r\nHost: target.test\r\nAuthorization: Bearer {token}\r\n\r\n"
    ).encode()
    encoded = json.dumps(body).encode()
    response_raw = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n\r\n"
    ).encode() + encoded
    return SimpleNamespace(
        request=SimpleNamespace(
            raw=request_raw,
            host="target.test",
            is_tls=True,
        ),
        response=SimpleNamespace(raw=response_raw),
    )


def _context(context: dict[str, object], tool_name: str) -> ToolContext[dict[str, object]]:
    return ToolContext(
        context=context,
        tool_name=tool_name,
        tool_call_id=f"call-{tool_name}",
        tool_arguments="{}",
    )


def test_identity_swap_removes_custom_auth_for_anonymous_control() -> None:
    headers = {
        "Host": "target.test",
        "X-Custom-Auth-Token": "owner-secret",
        "X-CSRF-Token": "csrf-value",
    }

    anonymous = _apply_identity(headers, {})
    attacker = _apply_identity(headers, {"X-Custom-Auth-Token": "attacker-secret"})

    assert "X-Custom-Auth-Token" not in anonymous
    assert anonymous["X-CSRF-Token"] == "csrf-value"
    assert attacker["X-Custom-Auth-Token"] == "attacker-secret"


@pytest.mark.asyncio
async def test_identity_to_hypothesis_public_workflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captures = {
        "request-a": _capture(
            "/api/orders/101",
            "secret-user-a",
            {"id": 101, "owner_id": "user-a"},
        ),
        "request-b": _capture(
            "/api/profile",
            "secret-user-b",
            {"id": "user-b"},
        ),
    }

    async def get_request(
        _client: object,
        request_id: str,
        **_kwargs: Any,
    ) -> SimpleNamespace:
        return captures[request_id]

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    context: dict[str, object] = {
        "caido_client": object(),
        "_detection_store": DetectionStore(),
    }

    for name, request_id in (("user-a", "request-a"), ("user-b", "request-b")):
        raw = await register_test_identity.on_invoke_tool(
            _context(context, "register_test_identity"),
            json.dumps({"name": name, "request_id": request_id}),
        )
        assert json.loads(raw)["success"] is True

    generated_raw = await generate_idor_hypotheses.on_invoke_tool(
        _context(context, "generate_idor_hypotheses"),
        "{}",
    )
    generated = json.loads(generated_raw)
    state_raw = await inspect_detection_state.on_invoke_tool(
        _context(context, "inspect_detection_state"),
        "{}",
    )
    state = json.loads(state_raw)

    assert generated["generated_count"] == 1
    assert generated["hypotheses"][0]["owner_identity"] == "user-a"
    assert len(state["identities"]) == 2
    assert "secret-user-a" not in state_raw
    assert "secret-user-b" not in state_raw
