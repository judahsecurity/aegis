"""Reproducible, secret-safe benchmark run records."""

from __future__ import annotations

import json
import platform
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


_FAILURE_STAGES = {
    "discovery",
    "authentication",
    "hypothesis_generation",
    "exploitation",
    "validation",
    "flag_extraction",
    "completed",
}


class BenchmarkRunRecorder:
    """Persist enough metadata to reproduce and diagnose a black-box run."""

    def __init__(
        self,
        storage_path: Path,
        *,
        scan_id: str,
        model: str,
        scan_mode: str,
        target_count: int,
        max_turns: int,
        max_budget_usd: float | None,
    ) -> None:
        self._path = storage_path
        self._lock = threading.RLock()
        self.record: dict[str, Any] = {
            "schema_version": 1,
            "scan_id": scan_id,
            "model": model,
            "scan_mode": scan_mode,
            "target_count": target_count,
            "max_turns": max_turns,
            "max_budget_usd": max_budget_usd,
            "python_version": platform.python_version(),
            "started_at": time.time(),
            "finished_at": None,
            "elapsed_seconds": None,
            "solved": False,
            "expected_value_present": None,
            "failure_stage": "discovery",
            "artifacts": [
                "coverage.json",
                "detection.json",
                "agents.db",
                "benchmark_run.json",
            ],
            "events": [],
            "metrics": {},
        }
        self._hydrate_or_persist()

    def _hydrate_or_persist(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.record.update(raw)
                    return
            except (OSError, TypeError, ValueError):
                pass
        self._persist()

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.record, ensure_ascii=False, sort_keys=True, default=str)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self._path.parent),
            prefix=f".{self._path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary_path = Path(temporary.name)
        temporary_path.chmod(0o600)
        temporary_path.replace(self._path)

    def mark_stage(self, stage: str, *, detail: str = "", evidence_ref: str = "") -> None:
        if stage not in _FAILURE_STAGES:
            raise ValueError(f"Unknown benchmark stage: {stage}")
        with self._lock:
            self.record["failure_stage"] = stage
            self.record["events"].append(
                {
                    "timestamp": time.time(),
                    "stage": stage,
                    "detail": detail[:500],
                    "evidence_ref": evidence_ref[:500],
                }
            )
            self.record["events"] = self.record["events"][-1000:]
            self._persist()

    def update_metrics(self, metrics: dict[str, Any]) -> None:
        with self._lock:
            self.record["metrics"].update(metrics)
            self._persist()

    def finish(
        self,
        *,
        solved: bool,
        expected_value_present: bool | None,
        failure_stage: str,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        if failure_stage not in _FAILURE_STAGES:
            raise ValueError(f"Unknown benchmark stage: {failure_stage}")
        with self._lock:
            finished_at = time.time()
            self.record.update(
                {
                    "finished_at": finished_at,
                    "elapsed_seconds": round(finished_at - float(self.record["started_at"]), 3),
                    "solved": bool(solved),
                    "expected_value_present": expected_value_present,
                    "failure_stage": "completed" if solved else failure_stage,
                }
            )
            if metrics:
                self.record["metrics"].update(metrics)
            self._persist()


def get_benchmark_recorder(ctx: Any) -> BenchmarkRunRecorder | None:
    raw = getattr(ctx, "context", ctx)
    inner = raw if isinstance(raw, dict) else {}
    recorder = inner.get("_benchmark_recorder")
    return recorder if isinstance(recorder, BenchmarkRunRecorder) else None
