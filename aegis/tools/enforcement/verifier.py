"""Evidence verification for testing thoroughness."""

from __future__ import annotations

from typing import Any, ClassVar

from aegis.tools.enforcement.tracker import HTTP_EXECUTION_TOOLS


class EvidenceVerifier:
    """Verify that testing evidence exists for each category."""

    VERIFICATION_QUESTIONS: ClassVar[dict[str, list[str]]] = {
        "auth": [
            "Tested login endpoint with invalid credentials",
            "Tested JWT token manipulation or weak secrets",
            "Tested session management (fixation, hijacking)",
            "Tested OAuth/SSO flow if present",
            "Tested password reset flow",
        ],
        "access_control": [
            "Tested IDOR on object references",
            "Tested privilege escalation (horizontal/vertical)",
            "Tested forced browsing to protected pages",
            "Tested HTTP method tampering",
        ],
        "injection": [
            "Tested SQL injection (union, blind, error-based)",
            "Tested XSS (reflected, stored, DOM)",
            "Tested command injection",
            "Tested SSTI on template parameters",
            "Tested XXE on XML endpoints",
            "Tested NoSQL injection",
        ],
        "server_side": [
            "Tested SSRF (internal services, cloud metadata)",
            "Tested path traversal / LFI",
            "Tested file upload vulnerabilities",
            "Tested insecure deserialization",
        ],
        "client_side": [
            "Tested CSRF on state-changing endpoints",
            "Tested clickjacking (X-Frame-Options)",
            "Tested open redirect",
            "Tested CORS misconfiguration",
        ],
        "configuration": [
            "Tested security headers (HSTS, CSP, etc.)",
            "Tested error handling (verbose errors)",
            "Tested information disclosure (versions, paths)",
            "Tested directory listing",
        ],
        "business_logic": [
            "Tested race conditions on critical operations",
            "Tested workflow bypass",
            "Tested input validation bypass",
        ],
        "api_security": [
            "Tested mass assignment",
            "Tested API authentication bypass",
            "Tested rate limiting",
            "Tested excessive data exposure",
        ],
    }

    def verify_category_evidence(self, category: str, context: dict[str, Any]) -> dict[str, Any]:
        """Check evidence in context for a category.

        Returns dict with:
            - passed: bool
            - checks: dict of check_name -> bool
            - missing: list of failed check names
        """
        test_evidence = context.get("test_evidence", {})
        category_evidence = test_evidence.get(category, {})

        tests = category_evidence.get("tests", [])
        tools_used = category_evidence.get("tools_used", [])
        endpoints_tested = category_evidence.get("endpoints_tested", [])
        findings = category_evidence.get("findings", [])
        no_vulns_confirmed = category_evidence.get("no_vulns_confirmed", False)

        checks = {
            "has_tests": len(tests) > 0,
            "has_endpoints": len(endpoints_tested) > 0,
            "has_findings_or_confirmed_clean": len(findings) > 0 or no_vulns_confirmed,
            "has_http_evidence": any(
                bool(t.get("evidence_ref"))
                and str(t.get("tool", "")).lower() in HTTP_EXECUTION_TOOLS
                for t in tests
                if isinstance(t, dict)
            ),
            "used_multiple_tools": len(set(tools_used)) >= 2
            or (len(tools_used) >= 1 and len(tests) >= 5),
        }

        passed = all(checks.values())
        missing = [k for k, v in checks.items() if not v]

        return {
            "passed": passed,
            "checks": checks,
            "missing": missing,
        }

    def get_verification_questions(self, category: str) -> list[str]:
        """Get verification questions for a category."""
        return self.VERIFICATION_QUESTIONS.get(category, [])
