"""Tests for reproducible, secret-safe benchmark run records."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from aegis.detection.benchmark import BenchmarkRunRecorder


if TYPE_CHECKING:
    from pathlib import Path


def test_benchmark_recorder_persists_stage_and_metrics(tmp_path: Path) -> None:
    path = tmp_path / "benchmark_run.json"
    recorder = BenchmarkRunRecorder(
        path,
        scan_id="scan-test",
        model="test-model",
        scan_mode="deep",
        target_count=1,
        max_turns=100,
        max_budget_usd=5.0,
    )
    recorder.mark_stage("authentication", detail="Two sessions clustered")
    recorder.update_metrics({"endpoint_count": 7, "identity_count": 2})
    recorder.finish(
        solved=False,
        expected_value_present=False,
        failure_stage="validation",
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scan_id"] == "scan-test"
    assert payload["failure_stage"] == "validation"
    assert payload["metrics"]["identity_count"] == 2
    assert payload["elapsed_seconds"] is not None
    assert path.stat().st_mode & 0o777 == 0o600
