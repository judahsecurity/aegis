"""Caido replay coverage is tied to a completed HTTP exchange."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool_context import ToolContext

from aegis.detection.store import DetectionStore
from aegis.tools.enforcement.tracker import get_tracker
from aegis.tools.proxy import caido_api
from aegis.tools.proxy.tools import list_requests, repeat_request


def _request_result() -> SimpleNamespace:
    request = SimpleNamespace(
        raw=b"GET /users/1 HTTP/1.1\r\nHost: target.test\r\n\r\n",
        host="target.test",
        is_tls=True,
    )
    return SimpleNamespace(request=request)


@pytest.mark.asyncio
async def test_successful_replay_records_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    async def get_request(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return _request_result()

    async def replay(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "session_id": "session-1",
            "status": "DONE",
            "error": None,
            "elapsed_ms": 12,
            "response_raw": b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    context = {"caido_client": object()}
    ctx = ToolContext(
        context=context,
        tool_name="repeat_request",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    raw = await repeat_request.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "request_id": "request-1",
                "modifications": {"url": "https://target.test/users/2"},
                "category": "access_control",
                "endpoint_template": "/users/{id}",
                "sub_category": "idor",
                "test_type": "cross-user object read",
                "parameter": "user_id",
                "payload_family": "adjacent-id",
                "auth_context": "user-a",
                "finding": False,
                "no_vulnerability_observed": True,
            }
        ),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["coverage_event"]["created"] is True
    events = get_tracker(context).get_category_events("access_control")
    assert len(events) == 1
    assert events[0]["endpoint"] == "/users/{id}"
    assert events[0]["evidence_ref"] == "caido:replay:session-1"
    assert events[0]["status_code"] == 403


@pytest.mark.asyncio
async def test_failed_replay_does_not_record_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    async def get_request(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return _request_result()

    async def replay(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "session_id": "session-2",
            "status": "ERROR",
            "error": "target unreachable",
            "elapsed_ms": 20,
            "response_raw": None,
        }

    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    monkeypatch.setattr(caido_api, "replay_send_raw", replay)
    context = {"caido_client": object()}
    ctx = ToolContext(
        context=context,
        tool_name="repeat_request",
        tool_call_id="call-2",
        tool_arguments="{}",
    )

    raw = await repeat_request.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "request_id": "request-1",
                "category": "access_control",
                "test_type": "cross-user object read",
                "no_vulnerability_observed": True,
            }
        ),
    )
    result = json.loads(raw)

    assert result["success"] is False
    assert "coverage_error" in result
    assert get_tracker(context).get_total_tests() == 0


@pytest.mark.asyncio
async def test_listing_requests_hydrates_sessions_and_request_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    request_metadata = SimpleNamespace(
        id="request-auth",
        host="target.test",
        port=443,
        method="PATCH",
        path="/api/profile",
        query="",
        is_tls=True,
        created_at=now,
    )
    response_metadata = SimpleNamespace(
        id="response-auth",
        status_code=200,
        length=30,
        created_at=now,
        roundtrip_time=5,
    )
    connection = SimpleNamespace(
        edges=[
            SimpleNamespace(
                cursor="cursor-1",
                node=SimpleNamespace(
                    request=request_metadata,
                    response=response_metadata,
                ),
            )
        ],
        page_info=SimpleNamespace(
            has_next_page=False,
            has_previous_page=False,
            start_cursor="cursor-1",
            end_cursor="cursor-1",
        ),
    )
    raw = (
        b"PATCH /api/profile HTTP/1.1\r\nHost: target.test\r\n"
        b"Authorization: Bearer secret\r\nContent-Type: application/json\r\n\r\n"
        b'{"role":"user"}'
    )
    captured = SimpleNamespace(
        request=SimpleNamespace(raw=raw, host="target.test", is_tls=True),
        response=SimpleNamespace(
            raw=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
        ),
    )

    async def list_captured(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return connection

    async def get_request(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return captured

    monkeypatch.setattr(caido_api, "list_requests_with_client", list_captured)
    monkeypatch.setattr(caido_api, "get_request_with_client", get_request)
    store = DetectionStore()
    context = {"caido_client": object(), "_detection_store": store}
    ctx = ToolContext(
        context=context,
        tool_name="list_requests",
        tool_call_id="call-list",
        tool_arguments="{}",
    )

    result = json.loads(await list_requests.on_invoke_tool(ctx, "{}"))
    endpoint = next(iter(store.endpoints.values()))

    assert result["success"] is True
    assert len(store.identities) == 1
    assert endpoint.parameters["body:role"].mutation_score >= 0.65
    assert "secret" not in json.dumps(store.snapshot())
