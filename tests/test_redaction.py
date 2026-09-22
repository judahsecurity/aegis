"""Tests for credential-safe persisted artifacts."""

from __future__ import annotations

from pathlib import Path

from aegis.redaction import REDACTED, redact_sensitive_data, redact_sensitive_text
from aegis.tools.tool_logs import save_tool_output


def test_text_redaction_removes_common_secret_forms() -> None:
    value = """DEEPSEEK_API_KEY=sk-secret
Authorization: Bearer bearer-secret
Cookie: session=cookie-secret
curl -u alice:password123 https://target.test
{"password":"json-secret"}
"""

    redacted = redact_sensitive_text(value)

    for secret in ("sk-secret", "bearer-secret", "cookie-secret", "password123", "json-secret"):
        assert secret not in redacted
    assert REDACTED in redacted


def test_nested_evidence_redacts_headers_and_body_credentials() -> None:
    safe = redact_sensitive_data(
        {
            "headers": {"Cookie": "session=secret", "Accept": "*/*"},
            "body": '{"password":"body-secret","name":"safe"}',
        }
    )

    assert safe["headers"]["Cookie"] == REDACTED
    assert "body-secret" not in safe["body"]
    assert safe["headers"]["Accept"] == "*/*"


def test_tool_logs_are_redacted_and_private(tmp_path) -> None:
    path = save_tool_output(
        tmp_path,
        "curl -H 'Authorization: Bearer command-secret' https://target.test",
        "Set-Cookie: session=output-secret",
    )

    assert path is not None
    log_path = Path(path)
    combined = tmp_path / "tool_logs" / "all_commands.log"
    content = log_path.read_text(encoding="utf-8") + combined.read_text(encoding="utf-8")
    assert "command-secret" not in content
    assert "output-secret" not in content
    assert log_path.stat().st_mode & 0o777 == 0o600
    assert combined.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "tool_logs").stat().st_mode & 0o777 == 0o700
