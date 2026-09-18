"""Tool for linking non-proxy security probes to durable execution evidence."""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool

from aegis.tools.enforcement.minimums import MANDATORY_CATEGORIES
from aegis.tools.enforcement.tracker import get_tracker


@function_tool(timeout=30, strict_mode=False)
async def record_test_evidence(
    ctx: RunContextWrapper,
    category: str,
    endpoint: str,
    test_type: str,
    tool: str,
    evidence_ref: str,
    sub_category: str = "",
    parameter: str = "",
    payload_family: str = "",
    auth_context: str = "anonymous",
    oracle: str = "response-differential",
    payload: str = "",
    status_code: int | None = None,
    finding: bool = False,
    no_vulnerability_observed: bool = False,
) -> str:
    """Record a completed security probe using a durable execution reference.

    Use this only after a tool actually ran. ``evidence_ref`` must identify the
    corresponding run artifact, such as a Caido request/replay id, tool-log
    filename, browser trace, or saved HTTP transcript. Merely planning a probe
    does not count.

    Exactly one outcome should normally be set: ``finding=true`` when the probe
    confirmed a weakness, or ``no_vulnerability_observed=true`` when the probe
    completed without confirming one. An inconclusive probe may leave both
    false, but it will not satisfy category completion requirements.
    """
    if category not in MANDATORY_CATEGORIES:
        return json.dumps(
            {
                "success": False,
                "error": f"Invalid category: {category}",
                "valid_categories": sorted(MANDATORY_CATEGORIES),
            }
        )
    required = {
        "endpoint": endpoint,
        "test_type": test_type,
        "tool": tool,
        "evidence_ref": evidence_ref,
    }
    missing = [name for name, value in required.items() if not str(value or "").strip()]
    if missing:
        return json.dumps(
            {
                "success": False,
                "error": f"Missing required fields: {', '.join(missing)}",
            }
        )
    if finding and no_vulnerability_observed:
        return json.dumps(
            {
                "success": False,
                "error": "A probe cannot be both a finding and a negative observation",
            }
        )

    event = get_tracker(ctx).log_test(
        category=category,
        endpoint=endpoint,
        test_type=test_type,
        tool=tool,
        sub_category=sub_category,
        payload=payload,
        parameter=parameter,
        payload_family=payload_family,
        auth_context=auth_context,
        oracle=oracle,
        evidence_ref=evidence_ref,
        status_code=status_code,
        finding=finding,
        no_vulnerability_observed=no_vulnerability_observed,
    )
    return json.dumps(
        {
            "success": True,
            "created": event["created"],
            "event_id": event["event_id"],
            "category": event["category"],
            "endpoint": event["endpoint"],
            "evidence_ref": event["evidence_ref"],
        }
    )
