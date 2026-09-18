"""Regression tests for execution-backed vulnerability coverage."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aegis.tools.enforcement.tracker import TestTracker as CoverageTracker
from aegis.tools.enforcement.tracker import get_tracker
from aegis.tools.enforcement.verifier import EvidenceVerifier


if TYPE_CHECKING:
    from pathlib import Path


def _record_probe(
    tracker: CoverageTracker,
    *,
    category: str = "configuration",
    endpoint: str = "/health",
    parameter: str = "header",
    payload_family: str = "missing-security-header",
    tool: str = "repeat_request",
    evidence_ref: str = "caido:replay:1",
    negative: bool = True,
) -> dict[str, object]:
    return tracker.log_test(
        category=category,
        endpoint=endpoint,
        test_type="security control probe",
        tool=tool,
        sub_category="headers",
        parameter=parameter,
        payload_family=payload_family,
        evidence_ref=evidence_ref,
        status_code=200,
        no_vulnerability_observed=negative,
    )


def test_exact_duplicate_probe_is_not_counted_twice() -> None:
    tracker = CoverageTracker()

    first = _record_probe(tracker)
    duplicate = _record_probe(tracker)

    assert first["created"] is True
    assert duplicate["created"] is False
    assert duplicate["event_id"] == first["event_id"]
    assert tracker.get_total_tests() == 1


def test_distinct_security_dimensions_are_unique_probes() -> None:
    tracker = CoverageTracker()

    _record_probe(tracker, parameter="X-Frame-Options")
    _record_probe(tracker, parameter="Content-Security-Policy")
    _record_probe(tracker, parameter="header", payload_family="verbose-error")

    assert tracker.get_category_stats("configuration")["unique_tests"] == 3


def test_query_payloads_do_not_inflate_unique_endpoints() -> None:
    tracker = CoverageTracker()

    _record_probe(tracker, endpoint="https://target.test/search?q=one", parameter="q")
    _record_probe(
        tracker,
        endpoint="https://target.test/search?q=two",
        parameter="q",
        payload_family="alternate-value",
    )

    stats = tracker.get_category_stats("configuration")
    assert stats["unique_tests"] == 2
    assert stats["unique_endpoints"] == 1


def test_duplicate_execution_merges_a_later_finding() -> None:
    tracker = CoverageTracker()
    arguments = {
        "category": "configuration",
        "endpoint": "/health",
        "test_type": "security control probe",
        "tool": "repeat_request",
        "sub_category": "headers",
        "parameter": "header",
        "payload_family": "missing-security-header",
    }

    first = tracker.log_test(**arguments, evidence_ref="caido:replay:1")
    duplicate = tracker.log_test(
        **arguments,
        evidence_ref="caido:replay:2",
        finding=True,
    )

    assert first["created"] is True
    assert duplicate["created"] is False
    assert duplicate["finding"] is True
    assert len(duplicate["observations"]) == 2
    assert tracker.get_total_tests() == 1
    assert tracker.get_total_findings() == 1


def test_minimums_reject_claims_without_evidence_or_outcome() -> None:
    tracker = CoverageTracker()
    tracker.log_test(
        category="configuration",
        endpoint="/health",
        test_type="claimed probe",
        tool="curl",
        sub_category="headers",
    )

    passed, reasons = tracker.check_minimums("configuration")

    assert passed is False
    assert any("execution evidence" in reason for reason in reasons)
    assert any("finding or a negative observation" in reason for reason in reasons)


def test_configuration_minimum_accepts_caido_http_evidence() -> None:
    tracker = CoverageTracker()
    for index in range(10):
        event = tracker.log_test(
            category="configuration",
            endpoint=f"/endpoint-{index % 5}",
            test_type="configuration probe",
            tool="repeat_request",
            sub_category="headers" if index % 2 == 0 else "errors",
            parameter=f"input-{index}",
            payload_family="control-check",
            evidence_ref=f"caido:replay:{index}",
            status_code=200,
            no_vulnerability_observed=True,
        )
        assert event["created"] is True

    passed, reasons = tracker.check_minimums("configuration")

    assert passed is True
    assert reasons == []


def test_shallow_child_context_uses_scan_wide_ledger() -> None:
    root_context: dict[str, object] = {"_test_tracker": CoverageTracker()}
    child_context = dict(root_context)

    _record_probe(get_tracker(child_context))

    assert get_tracker(root_context) is get_tracker(child_context)
    assert get_tracker(root_context).get_total_tests() == 1


def test_coverage_ledger_survives_resume(tmp_path: Path) -> None:
    storage_path = tmp_path / "coverage.json"
    tracker = CoverageTracker(storage_path)
    _record_probe(tracker)
    tracker.mark_category_completed("configuration")

    resumed = CoverageTracker(storage_path)

    assert resumed.get_total_tests() == 1
    assert resumed.completed_categories == {"configuration"}
    assert resumed.get_category_events("configuration")[0]["evidence_ref"] == "caido:replay:1"


def test_verifier_recognizes_evidence_backed_caido_replays() -> None:
    tests = [
        {
            "tool": "repeat_request",
            "evidence_ref": f"caido:replay:{index}",
        }
        for index in range(5)
    ]
    context = {
        "test_evidence": {
            "configuration": {
                "tests": tests,
                "tools_used": ["repeat_request"],
                "endpoints_tested": ["/one"],
                "findings": [],
                "no_vulns_confirmed": True,
            }
        }
    }

    result = EvidenceVerifier().verify_category_evidence("configuration", context)

    assert result["passed"] is True
    assert result["checks"]["has_http_evidence"] is True
