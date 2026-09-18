"""Tests for persistent attack-surface and hypothesis state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aegis.detection.store import DetectionStore


if TYPE_CHECKING:
    from pathlib import Path


def test_store_generates_and_restores_idor_hypothesis(tmp_path: Path) -> None:
    state_path = tmp_path / "detection.json"
    store = DetectionStore(state_path)
    store.register_identity(
        name="user-a",
        source_request_id="request-a",
        role="user",
        auth_material="authorization-a",
    )
    store.register_identity(
        name="user-b",
        source_request_id="request-b",
        role="user",
        auth_material="authorization-b",
    )
    endpoint = store.observe_request(
        request_id="request-a",
        method="GET",
        host="target.test",
        url_path="/api/orders/101",
        headers={"Authorization": "Bearer a"},
        body="",
        identity_name="user-a",
        status_code=200,
    )

    generated = store.generate_idor_hypotheses()

    assert endpoint.route_template == "/api/orders/{integer}"
    assert len(generated) == 1
    assert generated[0].parameter_location == "path"
    assert generated[0].owner_identity == "user-a"

    resumed = DetectionStore(state_path)
    assert len(resumed.endpoints) == 1
    assert set(resumed.identities) == {"user-a", "user-b"}
    assert generated[0].hypothesis_id in resumed.hypotheses
    assert state_path.stat().st_mode & 0o777 == 0o600


def test_store_auto_clusters_sessions_and_generates_authorization_candidates() -> None:
    store = DetectionStore()
    admin_endpoint = store.observe_request(
        request_id="admin-request",
        method="PATCH",
        host="target.test",
        url_path="/api/admin/users/7",
        headers={
            "Authorization": "Bearer admin-secret",
            "Content-Type": "application/json",
        },
        body='{"role":"user"}',
        status_code=200,
        response_content_type="application/json",
    )
    store.observe_request(
        request_id="user-request",
        method="GET",
        host="target.test",
        url_path="/api/profile",
        headers={"Authorization": "Bearer user-secret"},
        body="",
        status_code=200,
    )

    assert len(store.identities) == 2
    assert "privileged_route" in admin_endpoint.workflow_hints
    assert all("secret" not in identity.to_dict() for identity in store.identities.values())

    generated = store.generate_all_hypotheses()
    kinds = {item.hypothesis_type for item in generated}

    assert "horizontal_idor" in kinds
    assert "vertical_authorization" in kinds
    assert "mass_assignment" in kinds
    assert store.campaign_health()["high_priority_open"] >= 2


def test_campaign_health_detects_repeated_axis_without_growth() -> None:
    store = DetectionStore()
    request = {
        "request_id": "request-1",
        "method": "GET",
        "host": "target.test",
        "url_path": "/api/profile",
        "headers": {"Authorization": "Bearer user"},
        "body": "",
        "status_code": 200,
    }
    store.observe_request(**request)
    for _ in range(7):
        store.observe_request(**request)

    health = store.campaign_health()

    assert health["no_growth_streak"] >= 5
    assert health["axis_lock_in"] is True
    assert health["recommendation"] == "acquire_or_create_second_identity"
    assert len(health["competing_hypotheses"]) == 2
