"""Regression tests for evidence grading and campaign reconciliation."""

from __future__ import annotations

from aegis.detection.evidence import assess_http_evidence
from aegis.detection.store import DetectionStore


def _exchange(*, authenticated: bool, description: str, body: str, status: int) -> dict:
    headers = {"Cookie": "session=secret"} if authenticated else {}
    return {
        "request": {
            "method": "GET",
            "url": "https://target.test/order/300401/receipt",
            "headers": headers,
            "body": "",
        },
        "response": {"status_code": status, "headers": {}, "body": body},
        "description": description,
    }


def _verified_evidence() -> list[dict]:
    return [
        _exchange(
            authenticated=True,
            description=(
                "Authenticated as the non-owner; an order owned by a different user "
                "returns that user's private receipt."
            ),
            body="Order 300401: FLAG{proof}",
            status=200,
        ),
        _exchange(
            authenticated=False,
            description="Anonymous control: without a session the same request is rejected.",
            body="Redirecting",
            status=302,
        ),
    ]


def test_paired_protected_object_and_control_are_verified() -> None:
    assessment = assess_http_evidence(_verified_evidence())

    assert assessment.level == "verified"
    assert assessment.protected_observations == 1
    assert assessment.controls == 1
    assert assessment.distinct_auth_contexts == 2


def test_status_difference_alone_is_not_verified() -> None:
    evidence = [
        _exchange(authenticated=True, description="request one", body="ok", status=200),
        _exchange(authenticated=False, description="request two", body="no", status=302),
    ]

    assessment = assess_http_evidence(evidence)

    assert assessment.level == "insufficient"
    assert assessment.protected_observations == 0


def test_verified_report_promotes_matching_idor_hypothesis(tmp_path) -> None:
    store = DetectionStore(tmp_path / "detection.json")
    store.register_identity(
        name="owner",
        source_request_id="request-owner",
        role="user",
        auth_material="owner-secret",
    )
    store.register_identity(
        name="other",
        source_request_id="request-other",
        role="user",
        auth_material="other-secret",
    )
    store.observe_request(
        request_id="request-owner",
        method="GET",
        host="target.test",
        url_path="/order/300401/receipt",
        headers={"Cookie": "session=owner"},
        body="",
        identity_name="owner",
        status_code=200,
    )
    hypothesis = store.generate_idor_hypotheses()[0]

    updated = store.reconcile_report(
        report_id="vuln-0001",
        endpoint="/order/{id}/receipt",
        method="GET",
        assessment=assess_http_evidence(_verified_evidence()),
    )

    assert [item.hypothesis_id for item in updated] == [hypothesis.hypothesis_id]
    assert store.hypotheses[hypothesis.hypothesis_id].status == "confirmed"
    health = store.campaign_health()
    assert health["hypothesis_counts"]["confirmed"] == 1
    assert health["verified_findings"] == 1


def test_weak_report_does_not_confirm_matching_hypothesis(tmp_path) -> None:
    store = DetectionStore(tmp_path / "detection.json")
    store.register_identity(
        name="owner",
        source_request_id="request-owner",
        role="user",
        auth_material="owner-secret",
    )
    store.register_identity(
        name="other",
        source_request_id="request-other",
        role="user",
        auth_material="other-secret",
    )
    store.observe_request(
        request_id="request-owner",
        method="GET",
        host="target.test",
        url_path="/order/300401/receipt",
        headers={"Cookie": "session=owner"},
        body="",
        identity_name="owner",
        status_code=200,
    )
    hypothesis = store.generate_idor_hypotheses()[0]
    weak = [
        _exchange(authenticated=True, description="request one", body="ok", status=200),
        _exchange(
            authenticated=False,
            description="Anonymous control request",
            body="no",
            status=302,
        ),
    ]

    store.reconcile_report(
        report_id="vuln-0001",
        endpoint="/order/{id}/receipt",
        method="GET",
        assessment=assess_http_evidence(weak),
    )

    assert store.hypotheses[hypothesis.hypothesis_id].status == "inconclusive"
    assert store.campaign_health()["verified_findings"] == 0
