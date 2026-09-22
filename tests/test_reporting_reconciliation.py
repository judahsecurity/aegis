"""Integration regression for report persistence and detection promotion."""

from __future__ import annotations

import json

import pytest

from aegis.detection.benchmark import BenchmarkRunRecorder
from aegis.detection.store import DetectionStore
from aegis.report.state import (
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from aegis.tools.reporting.tool import _do_create


def _exchange(*, authenticated: bool, description: str, body: str, status: int) -> dict:
    return {
        "request": {
            "method": "GET",
            "url": "https://target.test/order/300401/receipt",
            "headers": {"Cookie": "session=report-secret"} if authenticated else {},
            "body": "",
        },
        "response": {"status_code": status, "headers": {}, "body": body},
        "description": description,
    }


@pytest.mark.asyncio
async def test_report_promotes_detection_and_persists_redacted_evidence(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_state = get_global_report_state()
    report_state = ReportState("test-run")
    report_state._run_dir = tmp_path
    set_global_report_state(report_state)
    store = DetectionStore(tmp_path / ".state" / "detection.json")
    store.register_identity(
        name="owner",
        source_request_id="request-owner",
        role="user",
        auth_material="owner-secret",
    )
    store.register_identity(
        name="other",
        source_request_id="request-other",
        role="user",
        auth_material="other-secret",
    )
    store.observe_request(
        request_id="request-owner",
        method="GET",
        host="target.test",
        url_path="/order/300401/receipt",
        headers={"Cookie": "session=owner"},
        body="",
        identity_name="owner",
        status_code=200,
    )
    hypothesis = store.generate_idor_hypotheses()[0]
    recorder = BenchmarkRunRecorder(
        tmp_path / ".state" / "benchmark_run.json",
        scan_id="test-run",
        model="test-model",
        scan_mode="deep",
        target_count=1,
        max_turns=100,
        max_budget_usd=10.0,
    )

    async def no_duplicate(*_args, **_kwargs) -> dict:
        return {"is_duplicate": False}

    async def no_recent_traffic(*_args, **_kwargs) -> list:
        return []

    monkeypatch.setattr("aegis.report.dedupe.check_duplicate", no_duplicate)
    monkeypatch.setattr("aegis.tools.reporting.tool._capture_recent_http", no_recent_traffic)
    evidence = [
        _exchange(
            authenticated=True,
            description="A non-owner retrieved an order owned by a different user.",
            body="FLAG{proof}",
            status=200,
        ),
        _exchange(
            authenticated=False,
            description="Anonymous control: without a session the request is rejected.",
            body="redirect",
            status=302,
        ),
    ]

    try:
        result = await _do_create(
            title="Broken object-level authorization",
            description="A user can retrieve another user's receipt.",
            impact="Private order data is exposed.",
            target="https://target.test",
            technical_analysis="Object ownership is not enforced.",
            poc_description="Request another user's order receipt.",
            poc_script_code="curl -H 'Cookie: session=report-secret' https://target.test",
            remediation_steps="Enforce ownership on every receipt lookup.",
            cvss_breakdown={
                "attack_vector": "N",
                "attack_complexity": "L",
                "privileges_required": "L",
                "user_interaction": "N",
                "scope": "U",
                "confidentiality": "H",
                "integrity": "N",
                "availability": "N",
            },
            endpoint="/order/{id}/receipt",
            method="GET",
            cve=None,
            cwe="CWE-639",
            code_locations=None,
            http_requests=evidence,
            inner_context={
                "_detection_store": store,
                "_benchmark_recorder": recorder,
            },
        )
    finally:
        set_global_report_state(old_state)  # type: ignore[arg-type]

    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["evidence_assessment"]["level"] == "verified"
    assert report["http_requests"][0]["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert store.hypotheses[hypothesis.hypothesis_id].status == "confirmed"
    assert recorder.record["failure_stage"] == "validation"
    persisted = (tmp_path / "vulnerabilities.json").read_text(encoding="utf-8")
    assert "report-secret" not in persisted
    request_files = list((tmp_path / "evidence" / "vuln-0001" / "requests").glob("*.txt"))
    assert len(request_files) == 2
    benchmark = json.loads(
        (tmp_path / ".state" / "benchmark_run.json").read_text(encoding="utf-8")
    )
    assert benchmark["metrics"]["verified_report_findings"] == 1
