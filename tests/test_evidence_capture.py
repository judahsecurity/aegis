"""Tests for durable, secret-safe finding evidence."""

from __future__ import annotations

from pathlib import Path

from aegis.tools.evidence_capture import EvidenceCapture


def test_paired_http_evidence_is_unique_redacted_and_private(tmp_path) -> None:
    capture = EvidenceCapture(str(tmp_path))
    request = {
        "method": "GET",
        "url": "https://target.test/order/7",
        "headers": {"Cookie": "session=cookie-secret"},
        "body": '{"password":"body-secret"}',
    }
    response = {
        "status_code": 200,
        "headers": {"Set-Cookie": "session=response-secret"},
        "body": "FLAG{benchmark-proof}",
    }

    positive = Path(
        capture.save_http_evidence(
            "vuln-0001",
            request=request,
            response=response,
            description="Different user protected object",
        )
    )
    control = Path(
        capture.save_http_evidence(
            "vuln-0001",
            request=request,
            response={"status_code": 302, "headers": {}, "body": "redirect"},
            description="Anonymous control",
        )
    )

    assert positive != control
    assert positive.exists() and control.exists()
    content = positive.read_text(encoding="utf-8")
    for secret in ("cookie-secret", "body-secret", "response-secret"):
        assert secret not in content
    assert "FLAG{benchmark-proof}" in content
    assert positive.stat().st_mode & 0o777 == 0o600
    assert positive.with_suffix(".json").stat().st_mode & 0o777 == 0o600
    assert positive.parent.stat().st_mode & 0o777 == 0o700
