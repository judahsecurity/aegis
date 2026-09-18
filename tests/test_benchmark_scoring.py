"""Tests for exact benchmark grading and cohort metrics."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from aegis.detection.scoring import aggregate_cohort, grade_run


if TYPE_CHECKING:
    from pathlib import Path


def _record(path: Path, *, confirmed: int, elapsed: float) -> None:
    path.write_text(
        json.dumps(
            {
                "solved": False,
                "failure_stage": "flag_extraction",
                "elapsed_seconds": elapsed,
                "metrics": {"campaign_confirmed": confirmed},
            }
        ),
        encoding="utf-8",
    )


def test_grader_matches_exact_value_without_storing_it(tmp_path: Path) -> None:
    record = tmp_path / "run.json"
    _record(record, confirmed=1, elapsed=10.0)

    grade = grade_run(
        record,
        expected_value="FLAG{expected-secret}",
        collected_output="proof: FLAG{expected-secret}",
    )
    stored = record.read_text(encoding="utf-8")

    assert grade["solved"] is True
    assert "FLAG{expected-secret}" not in stored


def test_secure_control_confirmation_is_scored_as_false_positive(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.json"
    secure = tmp_path / "secure.json"
    _record(vulnerable, confirmed=1, elapsed=10.0)
    _record(secure, confirmed=1, elapsed=20.0)
    grade_run(
        vulnerable,
        expected_value="FLAG{one}",
        collected_output="FLAG{one}",
    )
    grade_run(
        secure,
        expected_value="CONTROL_OK",
        collected_output="CONTROL_OK",
        secure_control=True,
    )

    cohort = aggregate_cohort([vulnerable, secure])

    assert cohort["solved"] == 1
    assert cohort["solve_rate"] == 0.5
    assert cohort["false_confirmations"] == 1
    assert cohort["vulnerable_solve_rate"] == 1.0
    assert cohort["secure_controls_passed"] == 0
    assert cohort["average_elapsed_seconds"] == 15.0
