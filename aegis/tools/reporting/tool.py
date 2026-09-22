"""``create_vulnerability_report`` — file a vuln finding with dedup + CVSS."""

from __future__ import annotations

import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from agents import RunContextWrapper, function_tool

from aegis.detection.evidence import assess_http_evidence
from aegis.redaction import redact_sensitive_data, redact_sensitive_text


logger = logging.getLogger(__name__)


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
            f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
            f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
            f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
        )
        c = CVSS3(vector)
        score = c.scores()[0]
        severity = c.severities()[0].lower()
    except Exception:
        logger.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
}


def _merge_http_evidence(
    supplied: list[dict[str, Any]] | None,
    captured: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Prefer finding-specific evidence and append unique proxy context."""
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*(supplied or []), *(captured or [])]:
        if not isinstance(item, dict):
            continue
        fingerprint = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        merged.append(item)
        if len(merged) >= 10:
            break
    return merged


async def _capture_recent_http(ctx: dict[str, Any], title: str) -> list[dict[str, Any]]:
    """Best-effort recent traffic capture while retaining the client that worked."""
    from aegis.tools.proxy import caido_api

    clients: list[Any] = []
    context_client = ctx.get("caido_client")
    if context_client is not None:
        clients.append(context_client)
    try:
        fresh_client = await caido_api.get_client()
        if fresh_client is not context_client:
            clients.append(fresh_client)
    except Exception as exc:  # noqa: BLE001 - supplied evidence remains available.
        logger.debug("Could not create a fresh Caido evidence client: %s", exc)

    list_result: Any = None
    working_client: Any = None
    for candidate in clients:
        try:
            list_result = await caido_api.list_requests_with_client(candidate, first=10)
            working_client = candidate
            break
        except Exception as exc:  # noqa: BLE001 - try the next connection.
            logger.debug("Caido evidence client is unavailable: %s", exc)
    if list_result is None or working_client is None:
        return []

    captured: list[dict[str, Any]] = []
    edges = list_result.edges if hasattr(list_result, "edges") else []
    for edge in edges[:5]:
        node = edge.node if hasattr(edge, "node") else None
        request_id = getattr(node, "id", None) if node is not None else None
        if not request_id:
            continue
        try:
            full = await caido_api.get_request_with_client(
                working_client,
                str(request_id),
                part="request",
            )
            if full is None:
                continue
            request_obj = full.request if hasattr(full, "request") else None
            response_obj = full.response if hasattr(full, "response") else None
            req_raw = request_obj.raw if request_obj is not None else None
            resp_raw = response_obj.raw if response_obj is not None else None
            parsed_req = (
                caido_api.parse_raw_request(
                    req_raw.decode("utf-8", errors="replace")
                    if isinstance(req_raw, bytes)
                    else str(req_raw or "")
                )
                if req_raw
                else None
            )
            parsed_resp = caido_api.parse_raw_response(resp_raw) if resp_raw else None
            if not parsed_req or not parsed_resp:
                continue
            host = getattr(request_obj, "host", "")
            path = getattr(request_obj, "path", "")
            captured.append(
                {
                    "request": {
                        "method": parsed_req.get("method", "GET"),
                        "url": f"{host}{path}",
                        "headers": parsed_req.get("headers", {}),
                        "body": parsed_req.get("body", ""),
                    },
                    "response": {
                        "status_code": parsed_resp.get("status_code", 0),
                        "headers": parsed_resp.get("headers", {}),
                        "body": parsed_resp.get("body", ""),
                    },
                    "description": f"Captured HTTP traffic for {title}",
                }
            )
        except Exception as exc:  # noqa: BLE001 - one bad request must not lose the report.
            logger.debug("Failed to fetch full request %s: %s", request_id, exc)
    return captured


async def _do_create(  # noqa: PLR0912, PLR0915
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    http_requests: list[dict[str, Any]] | None = None,
    screenshots: list[dict[str, Any]] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    inner_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
    }
    for name, msg in _REQUIRED_FIELDS.items():
        if not str(fields.get(name) or "").strip():
            errors.append(msg)

    if not isinstance(cvss_breakdown, dict) or not cvss_breakdown:
        errors.append("cvss_breakdown: must be an object with the 8 CVSS metrics")
        cvss_breakdown = {}
    else:
        for name, valid in _CVSS_VALID.items():
            value = cvss_breakdown.get(name)
            if value not in valid:
                errors.append(f"Invalid {name}: {value}. Must be one of: {valid}")

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)

    try:
        from aegis.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; vulnerability report not persisted")
            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        from aegis.report.dedupe import check_duplicate

        existing = report_state.get_existing_vulnerabilities()
        safe_title = redact_sensitive_text(title)
        safe_description = redact_sensitive_text(description)
        safe_impact = redact_sensitive_text(impact)
        safe_target = redact_sensitive_text(target)
        safe_analysis = redact_sensitive_text(technical_analysis)
        safe_poc_description = redact_sensitive_text(poc_description)
        safe_poc_code = redact_sensitive_text(poc_script_code)
        safe_remediation = redact_sensitive_text(remediation_steps)
        candidate = {
            "title": safe_title,
            "description": safe_description,
            "impact": safe_impact,
            "target": safe_target,
            "technical_analysis": safe_analysis,
            "poc_description": safe_poc_description,
            "poc_script_code": safe_poc_code,
            "endpoint": endpoint,
            "method": method,
        }
        dedupe = await check_duplicate(candidate, existing)
        if dedupe.get("is_duplicate"):
            duplicate_id = dedupe.get("duplicate_id", "")
            duplicate_title = next(
                (r.get("title", "Unknown") for r in existing if r.get("id") == duplicate_id),
                "",
            )
            return {
                "success": False,
                "error": (
                    f"Potential duplicate of '{duplicate_title}' "
                    f"(id={duplicate_id[:8]}...) — do not re-report the same vulnerability"
                ),
                "duplicate_of": duplicate_id,
                "duplicate_title": duplicate_title,
                "confidence": dedupe.get("confidence", 0.0),
                "reason": dedupe.get("reason", ""),
            }

        report_id = report_state.add_vulnerability_report(
            title=safe_title,
            description=safe_description,
            severity=severity,
            impact=safe_impact,
            target=safe_target,
            technical_analysis=safe_analysis,
            poc_description=safe_poc_description,
            poc_script_code=safe_poc_code,
            remediation_steps=safe_remediation,
            cvss=cvss_score,
            cvss_breakdown=cvss_breakdown,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=parsed_locations,
            agent_id=agent_id if isinstance(agent_id, str) else None,
            agent_name=agent_name if isinstance(agent_name, str) else None,
        )

        # Auto-capture evidence from Caido proxy
        try:
            from aegis.tools.evidence_capture import get_evidence_capture

            ctx = inner_context or {}
            caido_client = ctx.get("caido_client")
            logger.debug(
                "Evidence auto-capture: ctx_keys=%s, has_caido=%s, http_reqs=%d",
                list(ctx.keys()) if isinstance(ctx, dict) else "not-dict",
                caido_client is not None,
                len(http_requests) if http_requests else 0,
            )

            # Get the correct run directory from the global report state
            run_dir = report_state.get_run_dir()
            evidence = get_evidence_capture(str(run_dir))

            auto_http_requests = await _capture_recent_http(ctx, safe_title)
            # Agent-supplied evidence is tied to the finding. Recent proxy
            # traffic is supplemental and must never displace it.
            all_requests = _merge_http_evidence(http_requests, auto_http_requests)
            assessment = assess_http_evidence(all_requests)
            safe_requests = redact_sensitive_data(all_requests)
            logger.debug(
                "Evidence merge: agent=%d, auto=%d, total=%d, level=%s",
                len(http_requests) if http_requests else 0,
                len(auto_http_requests),
                len(all_requests),
                assessment.level,
            )

            # Save HTTP request/response evidence
            if safe_requests:
                for req in safe_requests:
                    evidence.save_http_evidence(
                        report_id,
                        request=req.get("request", {}),
                        response=req.get("response", {}),
                        description=req.get("description", ""),
                    )

            # Save screenshots
            screenshot_paths: list[dict[str, str]] = []
            if screenshots:
                for i, screenshot in enumerate(screenshots):
                    path = evidence.save_screenshot(
                        report_id,
                        screenshot.get("data", b""),
                        f"screenshot_{i:03d}.png",
                        screenshot.get("description", ""),
                    )
                    screenshot_paths.append({
                        "path": path,
                        "description": screenshot.get("description", ""),
                    })

            # Save PoC code
            if safe_poc_code:
                evidence.save_poc(report_id, safe_poc_code, "python")

            # Save findings summary
            evidence.save_findings_summary(report_id, {
                "title": safe_title,
                "severity": severity,
                "cvss": cvss_score,
                "target": safe_target,
                "endpoint": endpoint,
            })

            # Store evidence refs in the report for markdown rendering
            if safe_requests or screenshot_paths:
                report_state.update_vulnerability_evidence(
                    report_id,
                    http_requests=safe_requests if safe_requests else None,
                    screenshot_files=screenshot_paths if screenshot_paths else None,
                    evidence_assessment=assessment.to_dict(),
                )

            # Reconcile the report with the scan-wide detection campaign. A
            # 2xx/3xx differential by itself never promotes a hypothesis.
            from aegis.detection.store import DetectionStore

            detection_store = ctx.get("_detection_store")
            if isinstance(detection_store, DetectionStore):
                detection_store.reconcile_report(
                    report_id=report_id,
                    endpoint=endpoint or target,
                    method=method or "GET",
                    assessment=assessment,
                )

            from aegis.detection.benchmark import BenchmarkRunRecorder

            benchmark_recorder = ctx.get("_benchmark_recorder")
            if isinstance(benchmark_recorder, BenchmarkRunRecorder):
                benchmark_recorder.mark_stage(
                    "validation",
                    detail=f"Report {report_id} evidence graded {assessment.level}",
                    evidence_ref=f"vulnerabilities.json#{report_id}",
                )
                benchmark_recorder.update_metrics(
                    {
                        "reported_findings": len(report_state.vulnerability_reports),
                        "verified_report_findings": sum(
                            bool(item.get("verified"))
                            for item in (
                                detection_store.promoted_findings.values()
                                if isinstance(detection_store, DetectionStore)
                                else []
                            )
                        ),
                    }
                )

        except Exception as exc:  # noqa: BLE001 - report remains persisted.
            logger.warning("Failed to save evidence: %s", exc)

    except (ImportError, AttributeError) as e:
        logger.exception("create_vulnerability_report persistence failed")
        return {"success": False, "error": f"Failed to create vulnerability report: {e!s}"}
    else:
        logger.info(
            "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
            report_id,
            severity,
            cvss_score,
            title,
        )
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_requests: list[dict[str, Any]] | None = None,
    screenshots: list[dict[str, Any]] | None = None,
) -> str:
    """File a vulnerability report — one report per fully-verified finding.

    **When to file**: you have a concrete vulnerability with a working
    proof-of-concept and you're 100% sure it's a real issue.

    **When NOT to file**:

    - General security observations without a specific vulnerability.
    - Suspicions you haven't confirmed with a PoC.
    - Tracking multiple vulnerabilities at once — one report per vuln.
    - Re-reporting something you (or another agent) already filed.

    Automatic LLM-based **deduplication** rejects reports that describe
    the same root cause on the same asset as an existing report. If you
    get a ``duplicate_of`` response, do NOT retry — move on to other
    areas.

    **Customer-facing report rules** (the report is PDF-rendered for
    delivery):

    - No internal/system details: never mention paths like
      ``/workspace``, internal tools, agents, sandboxes, models, system
      prompts, internal errors / stack traces, or tester environment.
    - Tone: formal, objective, third-person, vendor-neutral, concise.
    - Standard finding structure: Overview → Severity & CVSS →
      Affected assets → Technical details → PoC (steps + code) →
      Impact → Remediation → Evidence (in technical_analysis).
    - Numbered steps allowed only in PoC and Remediation sections.
    - Avoid hedging language; be precise and non-vague.

    **White-box requirement**: when source is available, you MUST
    populate ``code_locations``. See the ``code_locations`` arg below
    for the full rules around ``fix_before`` / ``fix_after``,
    multi-part fixes, and informational-vs-actionable entries.

    **CVSS breakdown** is an object with all 8 metrics (each a single
    uppercase letter):

    - ``attack_vector``: ``N`` (Network), ``A`` (Adjacent), ``L``
      (Local), ``P`` (Physical)
    - ``attack_complexity``: ``L`` / ``H``
    - ``privileges_required``: ``N`` / ``L`` / ``H``
    - ``user_interaction``: ``N`` / ``R``
    - ``scope``: ``U`` (Unchanged) / ``C`` (Changed)
    - ``confidentiality`` / ``integrity`` / ``availability``: ``N`` /
      ``L`` / ``H``

    Example::

        {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H"
        }

    **CVE / CWE rules**: pass the bare ID only (``CVE-2024-1234``,
    ``CWE-89``) — no name, no parenthetical. Be 100% certain; if
    unsure, use ``web_search`` to verify the ID before passing, or omit
    the field entirely. Always prefer the most specific child CWE over
    a broad parent (CWE-89 not CWE-74; CWE-78 not CWE-77). Do NOT use
    broad/parent CWEs like CWE-74, CWE-20, CWE-200, CWE-284, or
    CWE-693.

    Common CWE references (use the ID only — names are listed here
    just for your lookup):

    - **Injection**: CWE-79 XSS, CWE-89 SQLi, CWE-78 OS Command
      Injection, CWE-94 Code Injection, CWE-77 Command Injection.
    - **Auth / Access**: CWE-287 Improper Authentication, CWE-862
      Missing Authorization, CWE-863 Incorrect Authorization, CWE-306
      Missing Auth for Critical Function, CWE-639 Authz Bypass via
      User-Controlled Key.
    - **Web**: CWE-352 CSRF, CWE-918 SSRF, CWE-601 Open Redirect,
      CWE-434 Unrestricted File Upload.
    - **Memory**: CWE-787 OOB Write, CWE-125 OOB Read, CWE-416 UAF,
      CWE-120 Classic Buffer Overflow.
    - **Data**: CWE-502 Deserialization of Untrusted Data, CWE-22
      Path Traversal, CWE-611 XXE.
    - **Crypto / Config**: CWE-798 Hard-coded Credentials, CWE-327
      Broken / Risky Crypto, CWE-311 Missing Encryption, CWE-916 Weak
      Password Hashing.

    Args:
        title: Specific finding title (e.g.
            ``"SQL Injection in /api/users login parameter"``). Don't
            include the CVE number in the title.
        description: How the vuln was discovered + what it is.
        impact: What an attacker achieves; business risk; data at risk.
        target: Affected URL / domain / repository.
        technical_analysis: The mechanism and root cause.
        poc_description: Step-by-step reproduction.
        poc_script_code: Working PoC (Python preferred).
        remediation_steps: Specific, actionable fix.
        cvss_breakdown: 8-metric object per the format above.
        endpoint: API path / Git path (e.g. ``/api/login``).
        method: HTTP method when relevant.
        cve: ``CVE-YYYY-NNNNN`` if certain, else omit.
        cwe: ``CWE-NNN`` (most specific child) if certain, else omit.
        code_locations: White-box findings — list of location objects.

            **How ``fix_before`` / ``fix_after`` work**: they're used as
            literal GitHub/GitLab PR suggestion blocks. When a reviewer
            accepts the suggestion, the platform replaces the **exact
            lines from ``start_line`` to ``end_line``** with
            ``fix_after``. Therefore:

            1. ``fix_before`` must be a **VERBATIM** copy of the source
               at those lines — same whitespace, indentation, line
               breaks. If it doesn't match character-for-character, the
               suggestion will corrupt the code when accepted.
            2. ``fix_after`` is the COMPLETE replacement for that
               entire block (may be more or fewer lines).
            3. ``start_line`` / ``end_line`` must precisely cover the
               lines in ``fix_before`` — no more, no less.

            **Multi-part fixes**: many fixes touch multiple
            non-contiguous parts of a file (e.g. add an import at the
            top AND change code lower down). Since each
            ``fix_before`` / ``fix_after`` pair covers ONE contiguous
            block, create **separate location entries** for each
            non-contiguous part. Use ``label`` to describe each part's
            role (``"Add escape helper import"``, ``"Sanitize input
            before SQL"``). Order primary fix first, supporting
            changes (imports, config) after.

            **Informational vs actionable**:
            - With ``fix_before`` / ``fix_after``: actionable fix
              (renders as a PR suggestion block).
            - Without them: informational context (e.g. showing the
              source of tainted data, or a sink that doesn't need
              direct editing).

            **Per-location fields**:
            - ``file`` (REQUIRED): path **relative** to repo root. No
              leading slash, no ``..``, no ``/workspace/`` prefix.
              Right: ``"src/db/queries.ts"``. Wrong:
              ``"/workspace/repo/src/db/queries.ts"``, ``"./src/x.py"``,
              ``"../../etc/passwd"``.
            - ``start_line`` (REQUIRED): 1-based; positive integer.
              Verify against the actual file — do NOT guess.
            - ``end_line`` (REQUIRED): 1-based; ``>= start_line``.
              Only equal to ``start_line`` when the block truly is one
              line.
            - ``snippet`` (optional): verbatim source at this range.
            - ``label`` (optional): short role description; especially
              important for multi-part fixes.
            - ``fix_before`` (optional): verbatim copy of the
              vulnerable code, lines ``start_line``-``end_line``.
            - ``fix_after`` (optional): complete replacement for that
              block; syntactically valid.

            **Common mistakes to avoid**:
            - Guessing line numbers instead of reading the file.
            - Paraphrasing / reformatting code in ``fix_before``.
            - Setting ``start_line == end_line`` when the vulnerable
              code spans multiple lines.
            - Bundling an import addition and a far-away code change
              into one location — split them.
            - Padding ``fix_before`` with surrounding context lines
              that aren't part of the fix.
            - Duplicating the same change across multiple locations.

        http_requests: HTTP request/response pairs to include as evidence.
            Each entry is a dict with:

            - ``request``: ``{"method": "POST", "url": "...", "headers": {}, "body": ""}``
            - ``response``: ``{"status_code": 200, "headers": {}, "body": ""}``
            - ``description``: optional context string

            If omitted, the tool auto-captures recent traffic from the
            Caido proxy (up to 5 requests with full headers and body).

        screenshots: Screenshot evidence. Each entry is a dict with:

            - ``data``: raw PNG bytes (read from disk with ``open(path, "rb").read()``)
            - ``description``: what the screenshot shows

            Take screenshots with ``agent-browser screenshot <path>`` via
            ``exec_command``, then read the file to get bytes. Include
            BEFORE (vulnerable state), DURING (exploit), and AFTER
            (result) screenshots.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        http_requests=http_requests,
        screenshots=screenshots,
        agent_id=agent_id,
        agent_name=agent_name,
        inner_context=inner,
    )
    return json.dumps(result, ensure_ascii=False, default=str)
