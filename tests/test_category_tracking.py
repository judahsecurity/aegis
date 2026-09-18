"""Category summaries cannot manufacture probe coverage."""

from __future__ import annotations

import json

import pytest
from agents.tool_context import ToolContext

from aegis.tools.enforcement.evidence_tool import record_test_evidence
from aegis.tools.enforcement.tracker import get_tracker
from aegis.tools.todo.tools import track_category_tested


@pytest.mark.asyncio
async def test_declared_summary_does_not_create_tests() -> None:
    context: dict[str, object] = {}
    ctx = ToolContext(
        context=context,
        tool_name="track_category_tested",
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    raw = await track_category_tested.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "category": "configuration",
                "tools_used": '["curl"]',
                "endpoints_tested": '["/one", "/two", "/three", "/four", "/five"]',
                "test_count": 100,
                "findings_count": 0,
            }
        ),
    )
    result = json.loads(raw)

    assert result["success"] is False
    assert result["stats"]["unique_tests"] == 0
    assert result["stats"]["evidence_backed_tests"] == 0
    assert "configuration" not in context["tested_categories"]


@pytest.mark.asyncio
async def test_record_test_evidence_links_non_proxy_execution() -> None:
    context: dict[str, object] = {}
    ctx = ToolContext(
        context=context,
        tool_name="record_test_evidence",
        tool_call_id="call-2",
        tool_arguments="{}",
    )

    raw = await record_test_evidence.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "category": "injection",
                "endpoint": "/search",
                "test_type": "boolean SQL injection",
                "tool": "sqlmap",
                "evidence_ref": "tool-logs/sqlmap-001.txt",
                "sub_category": "sqli",
                "parameter": "q",
                "payload_family": "boolean-blind",
                "no_vulnerability_observed": True,
            }
        ),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["created"] is True
    assert get_tracker(context).get_category_stats("injection")["unique_tests"] == 1


@pytest.mark.asyncio
async def test_record_test_evidence_requires_a_durable_reference() -> None:
    context: dict[str, object] = {}
    ctx = ToolContext(
        context=context,
        tool_name="record_test_evidence",
        tool_call_id="call-3",
        tool_arguments="{}",
    )

    raw = await record_test_evidence.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "category": "injection",
                "endpoint": "/search",
                "test_type": "boolean SQL injection",
                "tool": "sqlmap",
                "evidence_ref": "",
            }
        ),
    )
    result = json.loads(raw)

    assert result["success"] is False
    assert "evidence_ref" in result["error"]
    assert get_tracker(context).get_total_tests() == 0
