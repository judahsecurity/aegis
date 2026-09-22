"""Tool output logging — saves shell command outputs to tool_logs/ directory."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from aegis.redaction import redact_sensitive_text

logger = logging.getLogger(__name__)

# Tool name patterns — order matters (first match wins)
_TOOL_PATTERNS: list[tuple[str, str]] = [
    # Dedicated security tools (highest priority)
    (r'\bnmap\b', "nmap"),
    (r'\bnuclei\b', "nuclei"),
    (r'\bsqlmap\b', "sqlmap"),
    (r'\bffuf\b', "ffuf"),
    (r'\bsubfinder\b', "subfinder"),
    (r'\bhttpx\b', "httpx"),
    (r'\bkatana\b', "katana"),
    (r'\bgospider\b', "gospider"),
    (r'\bnaabu\b', "naabu"),
    (r'\bdirsearch\b', "dirsearch"),
    (r'\barjun\b', "arjun"),
    (r'\bwafw00f\b', "wafw00f"),
    (r'\bhydra\b', "hydra"),
    (r'\bcrackmapexec\b', "crackmapexec"),
    (r'\benum4linux\b', "enum4linux"),
    (r'\bresponder\b', "responder"),
    (r'\bkerbrute\b', "kerbrute"),
    (r'\bimpacket-', "impacket"),
    (r'\bsemgrep\b', "semgrep"),
    (r'\bgitleaks\b', "gitleaks"),
    (r'\btrufflehog\b', "trufflehog"),
    (r'\btrivy\b', "trivy"),
    (r'\bbandit\b', "bandit"),
    # HTTP tools
    (r'\bcurl\b', "curl"),
    (r'\bwget\b', "wget"),
    # Browser
    (r'\bagent-browser\b', "agent_browser"),
    # Package management
    (r'\bpip\s+install\b', "pip_install"),
    (r'\bapt-get\b', "apt"),
    (r'\bgit\s+clone\b', "git_clone"),
    # System commands (lower priority)
    (r'\bpython3?\b', "python"),
    (r'\bls\b', "shell"),
    (r'\bcd\b', "shell"),
    (r'\bcat\b', "shell"),
    (r'\becho\b', "shell"),
    (r'\bmkdir\b', "shell"),
    (r'\bgrep\b', "shell"),
    (r'\bfind\b', "shell"),
    (r'\bhead\b', "shell"),
    (r'\btail\b', "shell"),
    (r'\bwc\b', "shell"),
    (r'\bnslookup\b', "shell"),
    (r'\bpwd\b', "shell"),
    (r'\bhostname\b', "shell"),
    (r'\btimeout\b', "shell"),
]


def _strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return re.sub(r'\[[\d;]*m', '', text)


def _strip_comment_prefix(command: str) -> str:
    """Remove leading comment lines from a command."""
    lines = command.strip().splitlines()
    # Find first non-comment line
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return command.strip()


def _detect_tool_name(command: str) -> str:
    """Detect which tool is being used from the command string."""
    # Strip ANSI escape codes first
    cleaned = _strip_ansi_codes(command)
    # Strip comments and get the actual command
    cleaned = _strip_comment_prefix(cleaned)
    # Handle "cd /path && command" patterns
    if "&&" in cleaned:
        parts = cleaned.split("&&")
        cleaned = parts[-1].strip()
    # Handle "timeout N command" prefix
    cleaned = re.sub(r'^timeout\s+\d+\s+', '', cleaned)
    # Handle "echo 'y' | command" pipe
    if "|" in cleaned:
        parts = cleaned.split("|")
        cleaned = parts[-1].strip()

    cleaned_lower = cleaned.lower()

    for pattern, tool_name in _TOOL_PATTERNS:
        if re.search(pattern, cleaned_lower):
            return tool_name

    return "other"


# Counter per tool type to avoid overwriting
_counters: dict[str, int] = {}


def _get_next_filename(tool_logs_dir: Path, tool_name: str) -> str:
    """Get next available filename for a tool type."""
    counter = _counters.get(tool_name, 0) + 1
    _counters[tool_name] = counter
    return f"{tool_name}_{counter:03d}.txt"


def save_tool_output(
    run_dir: str | Path,
    command: str,
    output: str,
    agent_id: str = "",
) -> str | None:
    """Save a tool's command and output to the tool_logs directory.

    Args:
        run_dir: Path to the scan run directory.
        command: The shell command that was executed.
        output: The output returned by the command.
        agent_id: Optional agent identifier.

    Returns:
        Path to the saved log file, or None on failure.
    """
    try:
        run_path = Path(run_dir)
        tool_logs_dir = run_path / "tool_logs"
        tool_logs_dir.mkdir(parents=True, exist_ok=True)
        tool_logs_dir.chmod(0o700)

        safe_command = redact_sensitive_text(command)
        safe_output = redact_sensitive_text(output)

        tool_name = _detect_tool_name(safe_command)
        filename = _get_next_filename(tool_logs_dir, tool_name)
        filepath = tool_logs_dir / filename

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        content = f"""{'=' * 70}
Tool: {tool_name}
Command: {safe_command}
Timestamp: {timestamp}
Agent: {agent_id or 'root'}
{'=' * 70}

{safe_output}
"""

        filepath.write_text(content, encoding="utf-8")
        filepath.chmod(0o600)

        # Also save a combined log of all commands
        combined_log = tool_logs_dir / "all_commands.log"
        with combined_log.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{tool_name}] {safe_command[:200]}\n")
        combined_log.chmod(0o600)

        logger.debug("Saved tool output: %s", filepath)
        return str(filepath)

    except Exception as exc:
        logger.debug("Failed to save tool output: %s", exc)
        return None
