"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from aegis.core.agents import coordinator_from_context


logger = logging.getLogger(__name__)

# Categories that MUST be tested before scan can finish
_MANDATORY_CATEGORIES = {
    "auth": "Authentication & Session",
    "access_control": "Access Control",
    "injection": "Injection",
    "server_side": "Server-Side",
    "client_side": "Client-Side",
    "configuration": "Configuration & Infrastructure",
    "business_logic": "Business Logic",
    "api_security": "API Security",
}


def _check_coverage(ctx: RunContextWrapper) -> list[str]:
    """Check which mandatory categories have been tested with minimum enforcement."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    from aegis.tools.enforcement.tracker import get_tracker

    tracker = get_tracker(ctx)
    tested = tracker.completed_categories
    inner["tested_categories"] = tested

    missing = []

    # Stage 1: Check all 8 categories are marked
    for cat_id, cat_name in _MANDATORY_CATEGORIES.items():
        if cat_id not in tested:
            missing.append(f"{cat_id} ({cat_name}) — NOT TESTED")

    # Stage 2: Check minimum tests per category using TestTracker
    if not missing:  # Only check minimums if all categories are marked
        for cat_id in _MANDATORY_CATEGORIES:
            passed, reasons = tracker.check_minimums(cat_id)
            if not passed:
                missing.append(f"{cat_id} — minimums not met: {'; '.join(reasons)}")

    # Stage 3: Check evidence quality
    if not missing:  # Only check evidence if minimums are met
        from aegis.tools.enforcement.verifier import EvidenceVerifier

        verifier = EvidenceVerifier()
        test_evidence = inner.setdefault("test_evidence", {})

        for cat_id in _MANDATORY_CATEGORIES:
            test_evidence[cat_id] = tracker.category_evidence(cat_id)
            evidence_result = verifier.verify_category_evidence(cat_id, inner)
            if not evidence_result["passed"]:
                missing.append(
                    f"{cat_id} — missing evidence: {', '.join(evidence_result['missing'])}"
                )

    # High-confidence queued work is a real completion blocker. This prevents
    # the agent from satisfying category counts while abandoning concrete,
    # executable authorization hypotheses discovered during the scan.
    from aegis.detection.store import DetectionStore

    detection_store = inner.get("_detection_store")
    if isinstance(detection_store, DetectionStore):
        health = detection_store.campaign_health()
        if health["high_priority_open"]:
            missing.append(
                "detection campaign — "
                f"{health['high_priority_open']} high-priority hypotheses remain open; "
                "run the detection campaign or resolve them before finishing"
            )

    return missing


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    ctx: RunContextWrapper | None = None,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")

    # Coverage is a hard completion condition. Repeated finish attempts do not
    # manufacture evidence or turn an incomplete scan into a complete one.
    if ctx is not None:
        missing = _check_coverage(ctx)
        if missing:
            errors.append(
                f"CRITICAL: The following {len(missing)} categories were NOT tested: "
                + ", ".join(missing)
                + ". You MUST test ALL categories before finishing. "
                + "Go back and test each missing category using the appropriate tools and skills."
            )

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from aegis.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_message`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. All vulnerabilities you found are filed via
       ``create_vulnerability_report`` (un-reported findings are not
       tracked and not credited).
    3. Don't double-report — one report per distinct vulnerability.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Customer-facing report rules** (this output is rendered into the
    final PDF the client sees):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. MUST include
          which of the 8 mandatory testing categories were completed
          (Authentication & Session, Access Control, Injection, Server-Side,
          Client-Side, Configuration, Business Logic, API Security).
          **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        ctx=ctx,
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)
