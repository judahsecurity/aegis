import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from agents.usage import Usage

from aegis.core.paths import run_dir_for
from aegis.redaction import redact_sensitive_data, redact_sensitive_text
from aegis.report.usage import LLMUsageLedger
from aegis.report.writer import (
    read_run_record,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)
from aegis.telemetry import posthog, scarf


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "completed_with_budget_limit"}

_global_report_state: Optional["ReportState"] = None


def get_global_report_state() -> Optional["ReportState"]:
    return _global_report_state


def set_global_report_state(report_state: "ReportState") -> None:
    global _global_report_state  # noqa: PLW0603
    _global_report_state = report_state


class ReportState:
    """Per-scan product artifact state plus artifact writer.

    The Agents SDK owns model/tool execution, tracing, and conversation
    persistence. This store keeps only Aegis-owned scan artifacts and
    report metadata. Live UI projections belong to the interface layer.

    It does not consume SDK tracing processors.
    """

    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self._llm_usage = LLMUsageLedger()
        self.run_record: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "status": "running",
            "targets_info": [],
            "llm_usage": self._build_llm_usage_record(),
        }
        self._run_dir: Path | None = None
        self._saved_vuln_ids: set[str] = set()

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = run_dir_for(run_dir_name)
            self._run_dir.mkdir(parents=True, exist_ok=True)

        return self._run_dir

    def hydrate_from_run_dir(self) -> None:
        """Reload prior-scan state from ``{run_dir}/`` for resume.

        Restores:

        - ``vulnerability_reports`` from ``vulnerabilities.json`` so
          :meth:`add_vulnerability_report` doesn't allocate a colliding
          ``vuln-0001`` and overwrite the prior on-disk MD.
        - ``run_record`` from ``run.json`` so timestamps, run inputs,
          status, and final report state have one public source of truth.

        Idempotent on missing files (fresh runs land here too via the
        same code path). **Raises on corruption** — silently swallowing
        a corrupt ``vulnerabilities.json`` would let the next vuln
        allocate ``vuln-0001`` and overwrite the prior MD on disk
        (data loss). Caller is expected to fail the run loud and let
        the user inspect ``{run_dir}`` or pick a fresh ``--run-name``.
        """
        run_dir = self.get_run_dir()

        data = read_run_record(run_dir)
        if data:
            self.run_record.update(data)
            if isinstance(data.get("start_time"), str):
                self.start_time = data["start_time"]
            if isinstance(data.get("end_time"), str):
                self.end_time = data["end_time"]
            scan_results = data.get("scan_results")
            if isinstance(scan_results, dict):
                self.scan_results = scan_results
                self.final_scan_result = self._format_final_scan_result(scan_results)
            self._hydrate_llm_usage(data.get("llm_usage"))
            logger.info("report state hydrated run.json from %s", run_dir)

        json_path = run_dir / "vulnerabilities.json"
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is corrupt ({exc}); "
                    f"refusing to start fresh — that would overwrite prior "
                    f"vulnerability MDs on disk. Inspect or delete the run dir.",
                ) from exc
            if not isinstance(data, list):
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is not a list",
                )
            raw_reports = [r for r in data if isinstance(r, dict)]
            self.vulnerability_reports = [redact_sensitive_data(r) for r in raw_reports]
            for raw_report, report in zip(raw_reports, self.vulnerability_reports, strict=True):
                rid = report.get("id")
                # If hydration removed a secret, leave the id unsaved so the
                # next artifact flush also rewrites the Markdown copy.
                if isinstance(rid, str) and raw_report == report:
                    self._saved_vuln_ids.add(rid)
            logger.info(
                "report state hydrated %d vulnerability report(s)",
                len(self.vulnerability_reports),
            )

    def add_vulnerability_report(
        self,
        title: str,
        severity: str,
        description: str | None = None,
        impact: str | None = None,
        target: str | None = None,
        technical_analysis: str | None = None,
        poc_description: str | None = None,
        poc_script_code: str | None = None,
        remediation_steps: str | None = None,
        cvss: float | None = None,
        cvss_breakdown: dict[str, str] | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
        platform: str | None = None,
        app_package: str | None = None,
        app_version: str | None = None,
        decompiled_file: str | None = None,
        device_required: bool | None = None,
    ) -> str:
        title = redact_sensitive_text(title)
        description = redact_sensitive_text(description) if description else None
        impact = redact_sensitive_text(impact) if impact else None
        target = redact_sensitive_text(target) if target else None
        technical_analysis = (
            redact_sensitive_text(technical_analysis) if technical_analysis else None
        )
        poc_description = redact_sensitive_text(poc_description) if poc_description else None
        poc_script_code = redact_sensitive_text(poc_script_code) if poc_script_code else None
        remediation_steps = (
            redact_sensitive_text(remediation_steps) if remediation_steps else None
        )
        code_locations = redact_sensitive_data(code_locations) if code_locations else None
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report: dict[str, Any] = {
            "id": report_id,
            "title": title.strip(),
            "severity": severity.lower().strip(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        if description:
            report["description"] = description.strip()
        if impact:
            report["impact"] = impact.strip()
        if target:
            report["target"] = target.strip()
        if technical_analysis:
            report["technical_analysis"] = technical_analysis.strip()
        if poc_description:
            report["poc_description"] = poc_description.strip()
        if poc_script_code:
            report["poc_script_code"] = poc_script_code.strip()
        if remediation_steps:
            report["remediation_steps"] = remediation_steps.strip()
        if cvss is not None:
            report["cvss"] = cvss
        if cvss_breakdown:
            report["cvss_breakdown"] = cvss_breakdown
        if endpoint:
            report["endpoint"] = endpoint.strip()
        if method:
            report["method"] = method.strip()
        if cve:
            report["cve"] = cve.strip()
        if cwe:
            report["cwe"] = cwe.strip()
        if code_locations:
            report["code_locations"] = code_locations
        if agent_id:
            report["agent_id"] = agent_id
        if agent_name:
            report["agent_name"] = agent_name
        if platform:
            report["platform"] = platform
        if app_package:
            report["app_package"] = app_package
        if app_version:
            report["app_version"] = app_version
        if decompiled_file:
            report["decompiled_file"] = decompiled_file
        if device_required is not None:
            report["device_required"] = device_required

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity)
        scarf.finding(severity)

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        self.save_run_data()
        return report_id

    def update_vulnerability_evidence(
        self,
        report_id: str,
        http_requests: list[dict[str, Any]] | None = None,
        screenshot_files: list[dict[str, str]] | None = None,
        evidence_assessment: dict[str, Any] | None = None,
    ) -> None:
        """Attach evidence references to an existing vulnerability report."""
        for report in self.vulnerability_reports:
            if report.get("id") == report_id:
                if http_requests:
                    report["http_requests"] = redact_sensitive_data(http_requests)
                if screenshot_files:
                    report["screenshot_files"] = redact_sensitive_data(screenshot_files)
                if evidence_assessment:
                    report["evidence_assessment"] = redact_sensitive_data(evidence_assessment)
                self.save_run_data()
                logger.info("Updated evidence for %s", report_id)
                return
        logger.warning("update_vulnerability_evidence: report %s not found", report_id)

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
    ) -> None:
        """Record SDK-native token usage for one completed model run/cycle."""
        if self._llm_usage.record(
            agent_id=agent_id,
            agent_name=agent_name,
            model=model,
            usage=usage,
        ):
            self.save_run_data()

    def record_observed_llm_cost(self, cost: float) -> None:
        self._llm_usage.record_observed_cost(cost)

    def get_total_llm_usage(self) -> dict[str, Any]:
        return dict(self.run_record.get("llm_usage") or self._build_llm_usage_record())

    def get_total_llm_cost(self) -> float:
        """Live accumulated LLM cost, independent of the persisted run-record snapshot."""
        return self._llm_usage.total_cost

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> None:
        self.scan_results = {
            "scan_completed": True,
            "executive_summary": executive_summary.strip(),
            "methodology": methodology.strip(),
            "technical_analysis": technical_analysis.strip(),
            "recommendations": recommendations.strip(),
            "success": True,
        }

        self.final_scan_result = self._format_final_scan_result(self.scan_results)
        self.run_record["scan_results"] = self.scan_results

        logger.info("Updated scan final fields")
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")
        scarf.end(self, exit_reason="finished_by_tool")

    def finalize_from_persisted_findings(
        self,
        *,
        completed_categories: list[str] | None = None,
    ) -> None:
        """Write a deterministic terminal report when the LLM budget is reserved.

        This path uses only already-persisted findings. It does not ask the
        model for another summary, so a verified result cannot be lost while
        trying to spend the final budget on prose.
        """
        reports = list(self.vulnerability_reports)
        if not reports:
            return
        finding_lines = []
        recommendation_lines = []
        for report in reports:
            title = str(report.get("title") or "Security finding").strip()
            severity = str(report.get("severity") or "unknown").strip().title()
            endpoint = str(report.get("endpoint") or report.get("target") or "target").strip()
            finding_lines.append(f"- {severity}: {title} ({endpoint})")
            remediation = str(report.get("remediation_steps") or "").strip()
            if remediation:
                recommendation_lines.append(f"- {title}: {remediation}")
        category_text = ", ".join(sorted(completed_categories or [])) or "partial"
        self.scan_results = {
            "scan_completed": True,
            "completion_reason": "budget_limit_after_findings",
            "coverage_complete": False,
            "executive_summary": (
                f"The assessment identified {len(reports)} exploitable security "
                "finding(s). Results and reproduction evidence were preserved before "
                "the configured assessment budget was exhausted."
            ),
            "methodology": (
                "Authorized application testing combined endpoint discovery, controlled "
                "request replay, identity-aware comparisons, and negative controls. "
                f"Completed coverage categories at finalization: {category_text}."
            ),
            "technical_analysis": "Confirmed findings:\n" + "\n".join(finding_lines),
            "recommendations": (
                "Prioritize the confirmed findings, deploy fixes, and perform a focused "
                "retest.\n" + "\n".join(recommendation_lines)
            ),
            "success": True,
            "vulnerability_count": len(reports),
        }
        self.final_scan_result = self._format_final_scan_result(self.scan_results)
        self.run_record["scan_results"] = self.scan_results
        self.save_run_data(status="completed_with_budget_limit")

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_record["status"] = "running"
        self.run_record["end_time"] = None
        self.run_record.pop("scan_results", None)
        self.end_time = None
        self.scan_results = None
        self.final_scan_result = None
        self.run_record.update(
            {
                "targets_info": config.get("targets", []),
                "instruction": config.get("user_instructions", ""),
                "scan_mode": config.get("scan_mode", "deep"),
                "diff_scope": config.get("diff_scope", {"active": False}),
                "non_interactive": bool(config.get("non_interactive", False)),
                "local_sources": config.get("local_sources", []),
                "scope_mode": config.get("scope_mode", "auto"),
                "diff_base": config.get("diff_base"),
            }
        )

    def save_run_data(self, mark_complete: bool = False, status: str | None = None) -> None:
        if mark_complete:
            self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = "completed"
        elif status and self.run_record.get("status") not in _TERMINAL_STATUSES:
            current_status = self.run_record.get("status")
            if status == "stopped" and current_status in {"failed", "interrupted"}:
                status = str(current_status)
            if self.end_time is None:
                self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = status

        self._sync_llm_usage_record()
        self._save_artifacts()

    def cleanup(self, status: str = "stopped") -> None:
        self.save_run_data(status=status)

    def _format_final_scan_result(self, scan_results: dict[str, Any]) -> str:
        return f"""# Executive Summary

{str(scan_results.get("executive_summary", "")).strip()}

# Methodology

{str(scan_results.get("methodology", "")).strip()}

# Technical Analysis

{str(scan_results.get("technical_analysis", "")).strip()}

# Recommendations

{str(scan_results.get("recommendations", "")).strip()}
"""

    def _save_artifacts(self) -> None:
        """Write scan artifacts under ``run_dir``."""
        run_dir = self.get_run_dir()
        try:
            run_dir.mkdir(parents=True, exist_ok=True)

            if self.final_scan_result:
                write_executive_report(run_dir, self.final_scan_result)

            if self.vulnerability_reports:
                write_vulnerabilities(run_dir, self.vulnerability_reports, self._saved_vuln_ids)

            write_run_record(run_dir, self.run_record)

            logger.info("Essential scan data saved to: %s", run_dir)
        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _sync_llm_usage_record(self) -> None:
        self.run_record["llm_usage"] = self._build_llm_usage_record()

    def _build_llm_usage_record(self) -> dict[str, Any]:
        return self._llm_usage.to_record()

    def _hydrate_llm_usage(self, raw_usage: Any) -> None:
        self._llm_usage.hydrate(raw_usage)
        self._sync_llm_usage_record()


def litellm_cost_callback(
    kwargs: Any,
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    """LiteLLM ``success_callback`` adapter; forwards observed cost to the active scan."""
    cost: float | None = None
    raw = kwargs.get("response_cost") if isinstance(kwargs, dict) else None
    if isinstance(raw, int | float) and raw > 0:
        cost = float(raw)

    if cost is None:
        hidden = getattr(completion_response, "_hidden_params", None) or {}
        candidate = hidden.get("response_cost") if isinstance(hidden, dict) else None
        if isinstance(candidate, int | float) and candidate > 0:
            cost = float(candidate)
        else:
            headers = hidden.get("additional_headers") or {} if isinstance(hidden, dict) else {}
            raw = (
                headers.get("llm_provider-x-litellm-response-cost")
                if isinstance(headers, dict)
                else None
            )
            try:
                value = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                value = None
            if value is not None and value > 0:
                cost = value

    if cost is None or cost <= 0:
        return
    report_state = get_global_report_state()
    if report_state is None:
        return
    try:
        report_state.record_observed_llm_cost(cost)
    except Exception:
        logger.exception("Failed to record observed LiteLLM cost")
