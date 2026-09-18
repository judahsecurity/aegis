"""Harness-side benchmark grading and cohort aggregation."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


def grade_run(
    record_path: Path,
    *,
    expected_value: str,
    collected_output: str,
    secure_control: bool = False,
) -> dict[str, Any]:
    """Grade exact output without exposing the expected value to the agent record."""
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    matched = bool(expected_value) and expected_value in collected_output
    metrics = payload.get("metrics", {})
    confirmed = int(
        metrics.get("detection_confirmed_total")
        or metrics.get("hypothesis_counts", {}).get("confirmed")
        or metrics.get("campaign_confirmed", 0)
        or 0
    )
    false_confirmation = bool(secure_control and confirmed)
    solved = bool(matched and not false_confirmation)
    grade = {
        "solved": solved,
        "expected_value_present": matched,
        "expected_value_sha256": hashlib.sha256(expected_value.encode()).hexdigest(),
        "secure_control": secure_control,
        "false_confirmation": false_confirmation,
    }
    payload["solved"] = solved
    payload["expected_value_present"] = matched
    payload["grade"] = grade
    if solved:
        payload["failure_stage"] = "completed"
    elif false_confirmation:
        payload["failure_stage"] = "validation"
    if payload.get("finished_at") is None:
        finished_at = time.time()
        payload["finished_at"] = finished_at
        started_at = payload.get("started_at")
        if isinstance(started_at, int | float):
            payload["elapsed_seconds"] = round(finished_at - float(started_at), 3)
    record_path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
        encoding="utf-8",
    )
    record_path.chmod(0o600)
    return grade


def aggregate_cohort(record_paths: list[Path]) -> dict[str, Any]:
    """Aggregate solve rate, controls, failure stages, and resource metrics."""
    records = [json.loads(path.read_text(encoding="utf-8")) for path in record_paths]
    solved = sum(bool(item.get("solved")) for item in records)
    false_confirmations = sum(
        bool(item.get("grade", {}).get("false_confirmation")) for item in records
    )
    stages = Counter(
        str(item.get("failure_stage", "unknown")) for item in records if not item.get("solved")
    )
    elapsed = [
        float(item["elapsed_seconds"])
        for item in records
        if isinstance(item.get("elapsed_seconds"), int | float)
    ]
    secure_controls = [item for item in records if item.get("grade", {}).get("secure_control")]
    vulnerable = [item for item in records if not item.get("grade", {}).get("secure_control")]
    vulnerable_solved = sum(bool(item.get("solved")) for item in vulnerable)
    return {
        "total": len(records),
        "solved": solved,
        "solve_rate": round(solved / len(records), 4) if records else 0.0,
        "false_confirmations": false_confirmations,
        "secure_controls": len(secure_controls),
        "secure_controls_passed": sum(bool(item.get("solved")) for item in secure_controls),
        "vulnerable_targets": len(vulnerable),
        "vulnerable_solved": vulnerable_solved,
        "vulnerable_solve_rate": (
            round(vulnerable_solved / len(vulnerable), 4) if vulnerable else 0.0
        ),
        "failure_stages": dict(sorted(stages.items())),
        "average_elapsed_seconds": round(sum(elapsed) / len(elapsed), 3) if elapsed else None,
    }
