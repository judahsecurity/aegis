"""Completion must remain blocked until real coverage exists."""

from __future__ import annotations

from agents import RunContextWrapper

from aegis.detection.store import DetectionStore
from aegis.tools.finish.tool import _check_coverage, _do_finish


def test_repeated_finish_attempts_never_bypass_coverage() -> None:
    context: dict[str, object] = {}
    ctx = RunContextWrapper(context=context)

    results = [
        _do_finish(
            parent_id=None,
            executive_summary="Summary",
            methodology="Methodology",
            technical_analysis="Analysis",
            recommendations="Recommendations",
            ctx=ctx,
        )
        for _ in range(4)
    ]

    assert all(result["success"] is False for result in results)
    assert all(result["error"] == "Validation failed" for result in results)
    assert "_finish_forced" not in context
    assert "_finish_attempts" not in context


def test_high_priority_detection_hypothesis_blocks_completion() -> None:
    store = DetectionStore()
    store.register_identity(
        name="admin",
        source_request_id="request-admin",
        role="admin",
        auth_material="admin",
    )
    store.register_identity(
        name="user",
        source_request_id="request-user",
        role="user",
        auth_material="user",
    )
    store.observe_request(
        request_id="request-admin",
        method="GET",
        host="target.test",
        url_path="/api/admin/audit",
        headers={"Authorization": "Bearer admin"},
        body="",
        identity_name="admin",
        status_code=200,
    )
    store.generate_all_hypotheses()
    ctx = RunContextWrapper(context={"_detection_store": store})

    missing = _check_coverage(ctx)

    assert any("high-priority hypotheses remain open" in item for item in missing)
