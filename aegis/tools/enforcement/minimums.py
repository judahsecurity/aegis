"""Minimum requirement definitions for each testing category."""

from __future__ import annotations

from typing import Any


# Mandatory categories that MUST be tested before scan can finish
MANDATORY_CATEGORIES = {
    "auth": "Authentication & Session",
    "access_control": "Access Control",
    "injection": "Injection",
    "server_side": "Server-Side",
    "client_side": "Client-Side",
    "configuration": "Configuration & Infrastructure",
    "business_logic": "Business Logic",
    "api_security": "API Security",
}

# Minimum requirements per category
MINIMUM_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "auth": {
        "min_unique_tests": 15,
        "min_unique_endpoints": 3,
        "required_tools": {"curl"},
        "sub_categories": {"login", "jwt", "oauth", "session", "password_reset"},
        "min_sub_categories": 3,
    },
    "injection": {
        "min_unique_tests": 25,
        "min_unique_endpoints": 5,
        "required_tools": {"sqlmap", "curl"},
        "sub_categories": {"sqli", "nosqli", "xss", "ssti", "xxe", "cmdi"},
        "min_sub_categories": 4,
    },
    "server_side": {
        "min_unique_tests": 20,
        "min_unique_endpoints": 4,
        "required_tools": {"curl"},
        "sub_categories": {"ssrf", "path_traversal", "file_upload", "deserialization"},
        "min_sub_categories": 3,
    },
    "client_side": {
        "min_unique_tests": 15,
        "min_unique_endpoints": 3,
        "required_tools": {"curl"},
        "sub_categories": {"csrf", "xss_dom", "clickjacking", "open_redirect"},
        "min_sub_categories": 3,
    },
    "configuration": {
        "min_unique_tests": 10,
        "min_unique_endpoints": 5,
        "required_tools": {"curl"},
        "sub_categories": {"headers", "errors", "info_disclosure", "directory_listing"},
        "min_sub_categories": 2,
    },
    "business_logic": {
        "min_unique_tests": 10,
        "min_unique_endpoints": 2,
        "required_tools": {"curl"},
        "sub_categories": {"race_condition", "workflow_bypass", "price_manipulation"},
        "min_sub_categories": 2,
    },
    "api_security": {
        "min_unique_tests": 15,
        "min_unique_endpoints": 5,
        "required_tools": {"curl"},
        "sub_categories": {"mass_assignment", "graphql", "rate_limiting", "idor"},
        "min_sub_categories": 3,
    },
    "access_control": {
        "min_unique_tests": 15,
        "min_unique_endpoints": 3,
        "required_tools": {"curl"},
        "sub_categories": {"idor", "privilege_escalation", "forced_browsing"},
        "min_sub_categories": 2,
    },
}

# Time allocation per category (seconds)
TIME_ALLOCATION = {
    "recon": 5 * 60,  # 5 minutes
    "per_category": 3 * 60,  # 3 minutes each x 8 = 24 minutes
    "verification": 2 * 60,  # 2 minutes
    "reporting": 1 * 60,  # 1 minute
}

# Category -> skill file mapping for on-demand loading
CATEGORY_SKILL_MAP = {
    "auth": "vulnerabilities/authentication/testing",
    "access_control": "vulnerabilities/idor",
    "injection": "vulnerabilities/sql_injection",
    "server_side": "vulnerabilities/ssrf",
    "client_side": "vulnerabilities/csrf",
    "configuration": "vulnerabilities/information_disclosure",
    "business_logic": "vulnerabilities/business_logic",
    "api_security": "vulnerabilities/mass_assignment",
}

# Tool -> skill file mapping
TOOL_SKILL_MAP = {
    "sqlmap": "tooling/sqlmap",
    "nuclei": "tooling/nuclei",
    "ffuf": "tooling/ffuf",
    "nmap": "tooling/nmap",
    "run_api_scan": "tooling/api_fuzzing",
    "agent-browser": "tooling/agent_browser",
    "httpx": "tooling/httpx",
    "subfinder": "tooling/subfinder",
    "semgrep": "tooling/semgrep",
}
