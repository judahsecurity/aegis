"""Tests for deterministic terminal report generation at a budget boundary."""

from __future__ import annotations

from aegis.report.state import ReportState


def test_budget_finalization_survives_generic_cleanup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("aegis.report.state.run_dir_for", lambda _name: tmp_path)
    state = ReportState("test-run")
    state.vulnerability_reports = [
        {
            "id": "vuln-0001",
            "title": "Cross-user receipt disclosure",
            "severity": "high",
            "timestamp": "2026-09-21 12:00:00 UTC",
            "endpoint": "/order/{id}/receipt",
            "remediation_steps": "Enforce object ownership checks.",
        }
    ]

    state.finalize_from_persisted_findings(completed_categories=["access_control", "auth"])
    state.cleanup(status="stopped")

    assert state.run_record["status"] == "completed_with_budget_limit"
    assert state.scan_results is not None
    assert state.scan_results["scan_completed"] is True
    assert state.scan_results["coverage_complete"] is False
    assert state.final_scan_result is not None
    assert "Cross-user receipt disclosure" in state.final_scan_result
    assert (tmp_path / "penetration_test_report.md").exists()
