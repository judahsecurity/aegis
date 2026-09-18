"""Execution-backed coverage ledger shared by every agent in a scan."""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aegis.tools.enforcement.minimums import MINIMUM_REQUIREMENTS


HTTP_EXECUTION_TOOLS = {
    "agent-browser",
    "curl",
    "httpx",
    "repeat_request",
    "run_api_scan",
}

logger = logging.getLogger(__name__)


class TestTracker:
    """Track concrete security probes and evaluate category coverage.

    A probe is unique by the dimensions that materially change the security
    experiment. Tool choice alone does not create a new test, while changing a
    parameter, payload family, authentication context, or oracle does.

    The runner creates one tracker before any child agents are spawned. Child
    contexts are shallow copies, so every agent writes to this same ledger.
    """

    def __init__(self, storage_path: Path | None = None) -> None:
        self.tests: list[dict[str, Any]] = []
        self._test_keys: set[str] = set()
        self._category_tools: dict[str, set[str]] = {}
        self._category_endpoints: dict[str, set[str]] = {}
        self._category_sub_categories: dict[str, set[str]] = {}
        self.completed_categories: set[str] = set()
        self._storage_path = storage_path
        self._lock = threading.RLock()
        self._hydrate()

    def _hydrate(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        try:
            payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
            events = payload.get("tests", []) if isinstance(payload, dict) else []
            completed = payload.get("completed_categories", []) if isinstance(payload, dict) else []
            if not isinstance(events, list) or not isinstance(completed, list):
                logger.warning(
                    "Coverage state at %s has invalid collection fields; starting empty",
                    self._storage_path,
                )
                return
            for event in events:
                if not isinstance(event, dict) or not isinstance(event.get("dedupe_key"), str):
                    continue
                self.tests.append(event)
                self._test_keys.add(event["dedupe_key"])
                category = str(event.get("category", ""))
                self._category_tools.setdefault(category, set()).add(str(event.get("tool", "")))
                self._category_endpoints.setdefault(category, set()).add(
                    str(event.get("endpoint", ""))
                )
                sub_category = str(event.get("sub_category", ""))
                if sub_category:
                    self._category_sub_categories.setdefault(category, set()).add(sub_category)
            self.completed_categories.update(str(category) for category in completed)
        except (OSError, TypeError, ValueError):
            logger.exception(
                "Coverage state at %s is unreadable; starting empty", self._storage_path
            )

    def _persist(self) -> None:
        if self._storage_path is None:
            return
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {
                    "version": 1,
                    "tests": self.tests,
                    "completed_categories": sorted(self.completed_categories),
                },
                ensure_ascii=False,
                default=str,
            )
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self._storage_path.parent),
                prefix=f".{self._storage_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(payload)
                temporary_path = Path(temporary.name)
            temporary_path.replace(self._storage_path)
        except OSError:
            logger.exception("Failed to persist coverage state to %s", self._storage_path)

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:16] if value else ""

    @staticmethod
    def _normalize(value: str) -> str:
        return " ".join(str(value or "").strip().lower().split())

    @staticmethod
    def _normalize_endpoint(value: str) -> str:
        """Remove query payloads/fragments from an endpoint identity."""
        endpoint = str(value or "").strip()
        if not endpoint:
            return ""
        parsed = urlsplit(endpoint)
        if parsed.scheme or parsed.netloc:
            return urlunsplit(
                (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "")
            )
        return parsed.path or "/"

    def log_test(
        self,
        category: str,
        endpoint: str,
        test_type: str,
        tool: str,
        sub_category: str = "",
        payload: str = "",
        *,
        parameter: str = "",
        payload_family: str = "",
        auth_context: str = "anonymous",
        oracle: str = "response-differential",
        evidence_ref: str = "",
        status_code: int | None = None,
        finding: bool = False,
        no_vulnerability_observed: bool = False,
    ) -> dict[str, Any]:
        """Record a concrete probe and return its event plus ``created``.

        ``evidence_ref`` should point to the execution that produced the
        observation: a Caido request/replay id, tool-log path, browser trace,
        or another durable run artifact.
        """
        normalized = {
            "category": self._normalize(category),
            "endpoint": self._normalize_endpoint(endpoint),
            "test_type": self._normalize(test_type),
            "tool": self._normalize(tool),
            "sub_category": self._normalize(sub_category),
            "parameter": self._normalize(parameter),
            "payload_family": self._normalize(payload_family),
            "auth_context": self._normalize(auth_context) or "anonymous",
            "oracle": self._normalize(oracle) or "response-differential",
        }
        payload_hash = self._fingerprint(payload)
        key = "\x1f".join(
            (
                normalized["category"],
                normalized["endpoint"],
                normalized["test_type"],
                normalized["sub_category"],
                normalized["parameter"],
                normalized["payload_family"],
                normalized["auth_context"],
                normalized["oracle"],
                payload_hash,
            )
        )

        with self._lock:
            if key in self._test_keys:
                existing = next(t for t in self.tests if t["dedupe_key"] == key)
                observation = {
                    "evidence_ref": str(evidence_ref or "").strip(),
                    "status_code": status_code,
                    "finding": bool(finding),
                    "no_vulnerability_observed": bool(no_vulnerability_observed),
                    "timestamp": time.time(),
                }
                existing["observations"].append(observation)
                existing["finding"] = bool(existing["finding"] or finding)
                existing["no_vulnerability_observed"] = bool(
                    existing["no_vulnerability_observed"] or no_vulnerability_observed
                )
                if evidence_ref and not existing["evidence_ref"]:
                    existing["evidence_ref"] = str(evidence_ref).strip()
                if status_code is not None:
                    existing["status_code"] = status_code
                self._persist()
                return {**existing, "created": False}

            timestamp = time.time()
            event = {
                "event_id": f"probe-{uuid.uuid4().hex[:12]}",
                **normalized,
                "payload_hash": payload_hash,
                "evidence_ref": str(evidence_ref or "").strip(),
                "status_code": status_code,
                "finding": bool(finding),
                "no_vulnerability_observed": bool(no_vulnerability_observed),
                "timestamp": timestamp,
                "dedupe_key": key,
                "observations": [
                    {
                        "evidence_ref": str(evidence_ref or "").strip(),
                        "status_code": status_code,
                        "finding": bool(finding),
                        "no_vulnerability_observed": bool(no_vulnerability_observed),
                        "timestamp": timestamp,
                    }
                ],
            }
            self._test_keys.add(key)
            self.tests.append(event)
            category_id = normalized["category"]
            self._category_tools.setdefault(category_id, set()).add(normalized["tool"])
            self._category_endpoints.setdefault(category_id, set()).add(normalized["endpoint"])
            if normalized["sub_category"]:
                self._category_sub_categories.setdefault(category_id, set()).add(
                    normalized["sub_category"]
                )
            self._persist()
            return {**event, "created": True}

    def mark_category_completed(self, category: str) -> None:
        """Persist a category completion after its minimums pass."""
        with self._lock:
            self.completed_categories.add(self._normalize(category))
            self._persist()

    def get_category_events(self, category: str) -> list[dict[str, Any]]:
        """Return a copy of every probe recorded for a category."""
        category_id = self._normalize(category)
        with self._lock:
            return [dict(t) for t in self.tests if t["category"] == category_id]

    def get_category_stats(self, category: str) -> dict[str, Any]:
        """Get execution-backed statistics for one category."""
        category_id = self._normalize(category)
        with self._lock:
            events = [t for t in self.tests if t["category"] == category_id]
            return {
                "unique_tests": len(events),
                "unique_endpoints": len(self._category_endpoints.get(category_id, set())),
                "tools_used": set(self._category_tools.get(category_id, set())),
                "sub_categories": set(self._category_sub_categories.get(category_id, set())),
                "evidence_backed_tests": sum(bool(t.get("evidence_ref")) for t in events),
                "findings": sum(bool(t.get("finding")) for t in events),
                "negative_results": sum(bool(t.get("no_vulnerability_observed")) for t in events),
            }

    def check_minimums(self, category: str) -> tuple[bool, list[str]]:
        """Check whether recorded evidence meets the category requirements."""
        reqs = MINIMUM_REQUIREMENTS.get(category, {})
        stats = self.get_category_stats(category)
        missing: list[str] = []

        min_tests = reqs.get("min_unique_tests", 0)
        if stats["unique_tests"] < min_tests:
            missing.append(f"Only {stats['unique_tests']} unique tests, need {min_tests}")

        min_endpoints = reqs.get("min_unique_endpoints", 0)
        if stats["unique_endpoints"] < min_endpoints:
            missing.append(
                f"Only {stats['unique_endpoints']} endpoints tested, need {min_endpoints}"
            )

        required_tools = reqs.get("required_tools", set())
        missing_tools = {
            tool
            for tool in required_tools
            if not self._tool_requirement_met(tool, stats["tools_used"])
        }
        if missing_tools:
            missing.append(f"Missing required tools: {', '.join(sorted(missing_tools))}")

        min_subs = reqs.get("min_sub_categories", 0)
        if len(stats["sub_categories"]) < min_subs:
            missing.append(
                f"Only {len(stats['sub_categories'])} sub-categories tested, need {min_subs}"
            )

        if stats["evidence_backed_tests"] < stats["unique_tests"]:
            missing.append(
                f"Only {stats['evidence_backed_tests']} of {stats['unique_tests']} tests "
                "have execution evidence"
            )

        if stats["findings"] + stats["negative_results"] < stats["unique_tests"]:
            missing.append("Every test must record either a finding or a negative observation")

        return len(missing) == 0, missing

    @staticmethod
    def _tool_requirement_met(required: str, tools_used: set[str]) -> bool:
        """Treat the legacy ``curl`` requirement as HTTP execution evidence.

        Caido replays and browser/API clients are equivalent evidence sources
        for this purpose. Specialist requirements such as ``sqlmap`` remain
        exact so the minimum does not silently become weaker.
        """
        if required == "curl":
            return bool(HTTP_EXECUTION_TOOLS.intersection(tools_used))
        return required in tools_used

    def get_all_stats(self) -> dict[str, dict[str, Any]]:
        return {cat: self.get_category_stats(cat) for cat in MINIMUM_REQUIREMENTS}

    def get_total_tests(self) -> int:
        with self._lock:
            return len(self._test_keys)

    def get_total_findings(self) -> int:
        with self._lock:
            return sum(1 for t in self.tests if t.get("finding"))

    def category_evidence(self, category: str) -> dict[str, Any]:
        """Build the evidence shape consumed by the completion verifier."""
        events = self.get_category_events(category)
        return {
            "tests": events,
            "tools_used": sorted({str(t["tool"]) for t in events}),
            "endpoints_tested": sorted({str(t["endpoint"]) for t in events}),
            "findings": [t for t in events if t.get("finding")],
            "no_vulns_confirmed": bool(events)
            and all(t.get("finding") or t.get("no_vulnerability_observed") for t in events),
        }


def get_tracker(ctx: Any) -> TestTracker:
    """Get or create the scan-wide tracker from an SDK or plain context."""
    raw = getattr(ctx, "context", ctx)
    inner = raw if isinstance(raw, dict) else {}
    tracker = inner.get("_test_tracker")
    if not isinstance(tracker, TestTracker):
        tracker = TestTracker()
        inner["_test_tracker"] = tracker
    return tracker
