"""End-to-end test for the two-identity IDOR detector."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool_context import ToolContext

from aegis.detection.store import DetectionStore
from aegis.detection.tools import execute_idor_hypothesis
from aegis.tools.enforcement.tracker import TestTracker as CoverageTracker
from aegis.tools.proxy import caido_api


def _captured_request(raw: bytes, response_raw: bytes | None = None) -> SimpleNamespace:
    request = SimpleNamespace(raw=raw, host="target.test", is_tls=True)
    response = SimpleNamespace(raw=response_raw) if response_raw is not None else None
    return SimpleNamespace(request=request, response=response)


def _raw_request(path: str, token: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: target.test\r\nAuthorization: Bearer {token}\r\n\r\n"
    ).encode()


def _raw_response(status: int, body: dict[str, object]) -> bytes:
    reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}[status]
    encoded = json.dumps(body).encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n\r\n"
    ).encode() + encoded


@pytest.mark.asyncio
async def test_execute_idor_hypothesis_requires_two_confirmations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = DetectionStore()
    store.register_identity(
        name="user-a",
        source_request_id="request-a",
        role="user",
        auth_material="a",
    )
    store.register_identity(
        name="user-b",
        source_request_id="request-b",
        role="user",
        auth_material="b",
    )
    store.observe_request(
        request_id="request-a",
        method="GET",
        host="target.test",
        url_path="/api/orders/101",
        headers={"Authorization": "Bearer a"},
        body="",
        identity_name="user-a",
        status_code=200,
    )
    hypothesis = store.generate_idor_hypotheses()[0]
    captured = {
        "request-a": _captured_request(_raw_request("/api/orders/101", "a")),
        "request-b": _captured_request(_raw_request("/api/profile", "b")),
    }

    async def get_request(
        _client: object,
        request_id: str,
        **_kwargs: Any,
    ) -> SimpleNamespace:
        return captured[request_id]

    replay_count = 0

    async def replay(
        _client: object,
        *,
        raw: bytes,
        connection: object,
    ) -> dict[str, Any]:
        nonlocal replay_count
        del connection
        replay_count += 1
        request_text = raw.decode()
        if "Authorization:" not in request_text:
            response = _raw_response(401, {"error": "unauthorized"})
        elif "aegis-missing" in request_text or "/1000104 " in request_text:
            response = _raw_response(404, {"error": "not found"})
        else:
            response = _raw_response(
                200,
                {"id": 101, "owner_id": "user-a", "email": "owner@example.test"},
            )
        return {
            "session_id": f"session-{replay_count}",
            "status": "DONE",
            "error": None,
            "elapsed_ms": 5,
            "response_raw": response,
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    tracker = CoverageTracker()
    context = {
        "caido_client": object(),
        "_detection_store": store,
        "_test_tracker": tracker,
    }
    ctx = ToolContext(
        context=context,
        tool_name="execute_idor_hypothesis",
        tool_call_id="call-idor",
        tool_arguments="{}",
    )

    raw_result = await execute_idor_hypothesis.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "test_identity": "user-b",
            }
        ),
    )
    result = json.loads(raw_result)

    assert result["success"] is True
    assert result["confirmed"] is True
    assert len(result["sequences"]) == 2
    assert replay_count == 8
    assert store.hypotheses[hypothesis.hypothesis_id].status == "confirmed"
    assert tracker.get_category_stats("access_control")["unique_tests"] == 4
    assert all(
        len(event["observations"]) == 2 for event in tracker.get_category_events("access_control")
    )
