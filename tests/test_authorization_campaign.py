"""End-to-end tests for automatic authorization detection campaigns."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool_context import ToolContext

from aegis.detection.store import DetectionStore
from aegis.detection.tools import execute_authorization_hypothesis, run_detection_campaign
from aegis.tools.enforcement.tracker import TestTracker as CoverageTracker
from aegis.tools.proxy import caido_api


def _capture(raw: bytes) -> SimpleNamespace:
    return SimpleNamespace(
        request=SimpleNamespace(raw=raw, host="target.test", is_tls=True),
        response=None,
    )


def _response(status: int, body: dict[str, object]) -> bytes:
    reason = {
        200: "OK",
        401: "Unauthorized",
        403: "Forbidden",
        422: "Unprocessable Entity",
    }[status]
    encoded = json.dumps(body, separators=(",", ":")).encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n\r\n"
    ).encode() + encoded


def _context(store: DetectionStore, tool_name: str) -> ToolContext[dict[str, object]]:
    return ToolContext(
        context={
            "caido_client": object(),
            "_detection_store": store,
            "_test_tracker": CoverageTracker(),
        },
        tool_name=tool_name,
        tool_call_id=f"call-{tool_name}",
        tool_arguments="{}",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("lower_status", "expected"), [(200, True), (403, False)])
async def test_vertical_authorization_vulnerable_and_secure_controls(
    monkeypatch: pytest.MonkeyPatch,
    lower_status: int,
    expected: bool,
) -> None:
    store = DetectionStore()
    store.register_identity(
        name="admin",
        source_request_id="admin-request",
        role="admin",
        auth_material="admin-token",
    )
    store.register_identity(
        name="user",
        source_request_id="user-request",
        role="user",
        auth_material="user-token",
    )
    store.observe_request(
        request_id="admin-request",
        method="GET",
        host="target.test",
        url_path="/api/admin/audit",
        headers={"Authorization": "Bearer admin"},
        body="",
        identity_name="admin",
        status_code=200,
    )
    hypothesis = store.generate_bfla_hypotheses()[0]
    captured = {
        "admin-request": _capture(
            b"GET /api/admin/audit HTTP/1.1\r\nHost: target.test\r\n"
            b"Authorization: Bearer admin\r\n\r\n"
        ),
        "user-request": _capture(
            b"GET /api/profile HTTP/1.1\r\nHost: target.test\r\nAuthorization: Bearer user\r\n\r\n"
        ),
    }

    async def get_request(_client: object, request_id: str, **_kwargs: Any) -> SimpleNamespace:
        return captured[request_id]

    replay_count = 0

    async def replay(_client: object, *, raw: bytes, connection: object) -> dict[str, Any]:
        nonlocal replay_count
        del connection
        replay_count += 1
        text = raw.decode()
        if "Authorization:" not in text:
            response = _response(401, {"error": "unauthorized"})
        elif "Bearer user" in text and lower_status == 403:
            response = _response(403, {"error": "forbidden"})
        else:
            response = _response(
                200,
                {"id": 1, "email": "admin@example.test", "account_id": 7},
            )
        return {
            "session_id": f"session-{replay_count}",
            "status": "DONE",
            "error": None,
            "response_raw": response,
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    ctx = _context(store, "execute_authorization_hypothesis")
    raw = await execute_authorization_hypothesis.on_invoke_tool(
        ctx,
        json.dumps({"hypothesis_id": hypothesis.hypothesis_id, "test_identity": "user"}),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["confirmed"] is expected
    assert replay_count == (6 if expected else 3)


@pytest.mark.asyncio
@pytest.mark.parametrize(("accepts_role", "expected"), [(True, True), (False, False)])
async def test_mass_assignment_requires_repeatable_privileged_field_change(
    monkeypatch: pytest.MonkeyPatch,
    accepts_role: bool,
    expected: bool,
) -> None:
    store = DetectionStore()
    store.register_identity(
        name="user",
        source_request_id="update-request",
        role="user",
        auth_material="user-token",
    )
    store.observe_request(
        request_id="update-request",
        method="PATCH",
        host="target.test",
        url_path="/api/profile",
        headers={
            "Authorization": "Bearer user",
            "Content-Type": "application/json",
        },
        body='{"displayName":"Alice","role":"user"}',
        identity_name="user",
        status_code=200,
        response_content_type="application/json",
    )
    hypothesis = next(
        item
        for item in store.generate_mass_assignment_hypotheses()
        if item.parameter_name == "role"
    )
    captured = {
        "update-request": _capture(
            b"PATCH /api/profile HTTP/1.1\r\nHost: target.test\r\n"
            b"Authorization: Bearer user\r\nContent-Type: application/json\r\n\r\n"
            b'{"displayName":"Alice","role":"user"}'
        )
    }

    async def get_request(_client: object, request_id: str, **_kwargs: Any) -> SimpleNamespace:
        return captured[request_id]

    replay_count = 0

    async def replay(_client: object, *, raw: bytes, connection: object) -> dict[str, Any]:
        nonlocal replay_count
        del connection
        replay_count += 1
        text = raw.decode()
        if "Authorization:" not in text:
            response = _response(401, {"error": "unauthorized"})
        elif "__aegis_unknown_field__" in text:
            response = _response(422, {"error": "unknown field"})
        elif '"role":"admin"' in text and accepts_role:
            response = _response(200, {"id": 1, "role": "admin"})
        else:
            response = _response(200, {"id": 1, "role": "user"})
        return {
            "session_id": f"session-{replay_count}",
            "status": "DONE",
            "error": None,
            "response_raw": response,
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    ctx = _context(store, "execute_authorization_hypothesis")
    raw = await execute_authorization_hypothesis.on_invoke_tool(
        ctx,
        json.dumps({"hypothesis_id": hypothesis.hypothesis_id}),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["confirmed"] is expected
    assert replay_count == (8 if expected else 4)


@pytest.mark.asyncio
async def test_campaign_automatically_drains_highest_priority_hypothesis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = DetectionStore()
    store.register_identity(
        name="admin",
        source_request_id="admin-request",
        role="admin",
        auth_material="admin-token",
    )
    store.register_identity(
        name="user",
        source_request_id="user-request",
        role="user",
        auth_material="user-token",
    )
    store.observe_request(
        request_id="admin-request",
        method="GET",
        host="target.test",
        url_path="/api/admin/audit",
        headers={"Authorization": "Bearer admin"},
        body="",
        identity_name="admin",
        status_code=200,
    )
    captured = {
        "admin-request": _capture(
            b"GET /api/admin/audit HTTP/1.1\r\nHost: target.test\r\n"
            b"Authorization: Bearer admin\r\n\r\n"
        ),
        "user-request": _capture(
            b"GET /api/profile HTTP/1.1\r\nHost: target.test\r\nAuthorization: Bearer user\r\n\r\n"
        ),
    }

    async def get_request(_client: object, request_id: str, **_kwargs: Any) -> SimpleNamespace:
        return captured[request_id]

    replay_count = 0

    async def replay(_client: object, *, raw: bytes, connection: object) -> dict[str, Any]:
        nonlocal replay_count
        del connection
        replay_count += 1
        response = (
            _response(401, {"error": "unauthorized"})
            if b"Authorization:" not in raw
            else _response(200, {"id": 1, "email": "admin@example.test"})
        )
        return {
            "session_id": f"session-{replay_count}",
            "status": "DONE",
            "error": None,
            "response_raw": response,
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    ctx = _context(store, "run_detection_campaign")
    raw = await run_detection_campaign.on_invoke_tool(
        ctx,
        json.dumps({"max_hypotheses": 1, "minimum_priority": 0.75}),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["executed_count"] == 1
    assert result["confirmed_count"] == 1
    assert any(item.status == "confirmed" for item in store.hypotheses.values())
