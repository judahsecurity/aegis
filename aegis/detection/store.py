"""Persistent scan-wide attack surface, identities, and hypotheses."""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from aegis.detection.evidence import EvidenceAssessment, normalize_route
from aegis.detection.extractor import (
    auth_headers,
    content_type,
    extract_parameters,
    template_path,
    workflow_hints,
)
from aegis.detection.models import (
    EndpointRecord,
    HypothesisRecord,
    HypothesisStatus,
    IdentityRecord,
)


logger = logging.getLogger(__name__)

_PRIVILEGED_ROLES = {"admin", "administrator", "privileged", "staff", "superuser"}
_MASS_ASSIGNMENT_MUTATIONS = {
    "role": "admin",
    "roles": "admin",
    "admin": "true",
    "isAdmin": "true",
    "is_admin": "true",
    "verified": "true",
    "approved": "true",
}


class DetectionStore:
    """Thread-safe state shared by every agent and restored on resume."""

    def __init__(self, storage_path: Path | None = None) -> None:
        self.endpoints: dict[str, EndpointRecord] = {}
        self.identities: dict[str, IdentityRecord] = {}
        self.hypotheses: dict[str, HypothesisRecord] = {}
        self.promoted_findings: dict[str, dict[str, Any]] = {}
        self.campaign_events: list[dict[str, Any]] = []
        self._storage_path = storage_path
        self._lock = threading.RLock()
        self._hydrate()

    def _hydrate(self) -> None:
        if self._storage_path is None or not self._storage_path.exists():
            return
        try:
            payload = json.loads(self._storage_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return
            self.endpoints = {
                str(key): EndpointRecord.from_dict(value)
                for key, value in payload.get("endpoints", {}).items()
                if isinstance(value, dict)
            }
            self.identities = {
                str(key): IdentityRecord.from_dict(value)
                for key, value in payload.get("identities", {}).items()
                if isinstance(value, dict)
            }
            self.hypotheses = {
                str(key): HypothesisRecord.from_dict(value)
                for key, value in payload.get("hypotheses", {}).items()
                if isinstance(value, dict)
            }
            self.promoted_findings = {
                str(key): dict(value)
                for key, value in payload.get("promoted_findings", {}).items()
                if isinstance(value, dict)
            }
            self.campaign_events = [
                dict(item) for item in payload.get("campaign_events", []) if isinstance(item, dict)
            ][-500:]
        except (OSError, TypeError, ValueError):
            logger.exception(
                "Detection state at %s is unreadable; starting empty", self._storage_path
            )

    def _persist(self) -> None:
        if self._storage_path is None:
            return
        try:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                {
                    "version": 3,
                    "endpoints": {
                        key: endpoint.to_dict() for key, endpoint in self.endpoints.items()
                    },
                    "identities": {
                        key: identity.to_dict() for key, identity in self.identities.items()
                    },
                    "hypotheses": {
                        key: hypothesis.to_dict() for key, hypothesis in self.hypotheses.items()
                    },
                    "promoted_findings": self.promoted_findings,
                    "campaign_events": self.campaign_events[-500:],
                },
                ensure_ascii=False,
                default=str,
            )
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self._storage_path.parent),
                prefix=f".{self._storage_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(payload)
                temporary_path = Path(temporary.name)
            temporary_path.chmod(0o600)
            temporary_path.replace(self._storage_path)
        except OSError:
            logger.exception("Failed to persist detection state to %s", self._storage_path)

    def observe_request(
        self,
        *,
        request_id: str,
        method: str,
        host: str,
        url_path: str,
        headers: dict[str, str],
        body: str,
        identity_name: str = "",
        status_code: int | None = None,
        response_content_type: str = "",
        persist: bool = True,
    ) -> EndpointRecord:
        """Merge a captured request/response into the canonical surface."""
        route_template, _ = template_path(url_path)
        endpoint_key = f"{method.upper()} {host.lower()}{route_template}"
        parameters = extract_parameters(url_path, body, content_type(headers))
        endpoint_hints = workflow_hints(method, url_path, parameters)
        with self._lock:
            resolved_identity = identity_name
            if not resolved_identity:
                resolved_identity = self._discover_identity(request_id, headers)
            endpoint = self.endpoints.get(endpoint_key)
            endpoint_is_new = endpoint is None
            if endpoint is None:
                endpoint = EndpointRecord(
                    key=endpoint_key,
                    method=method.upper(),
                    host=host.lower(),
                    route_template=route_template,
                )
                self.endpoints[endpoint_key] = endpoint
            before_signature = (
                len(endpoint.parameters),
                len(endpoint.request_ids),
                len(endpoint.identities),
                len(endpoint.status_codes),
                len(endpoint.content_types),
                len(endpoint.workflow_hints),
            )
            for parameter in parameters:
                key = f"{parameter.location}:{parameter.name}"
                current = endpoint.parameters.get(key)
                if current is None or parameter.identifier_score > current.identifier_score:
                    endpoint.parameters[key] = parameter
            if request_id and request_id not in endpoint.request_ids:
                endpoint.request_ids.append(request_id)
            if resolved_identity and resolved_identity not in endpoint.identities:
                endpoint.identities.append(resolved_identity)
            if status_code is not None and status_code not in endpoint.status_codes:
                endpoint.status_codes.append(status_code)
            if response_content_type and response_content_type not in endpoint.content_types:
                endpoint.content_types.append(response_content_type)
            for hint in endpoint_hints:
                if hint not in endpoint.workflow_hints:
                    endpoint.workflow_hints.append(hint)
            after_signature = (
                len(endpoint.parameters),
                len(endpoint.request_ids),
                len(endpoint.identities),
                len(endpoint.status_codes),
                len(endpoint.content_types),
                len(endpoint.workflow_hints),
            )
            self._record_event(
                "surface_observed",
                axis=endpoint_key,
                state_changed=endpoint_is_new or before_signature != after_signature,
            )
            if persist:
                self._persist()
            return EndpointRecord.from_dict(endpoint.to_dict())

    def _discover_identity(self, request_id: str, headers: dict[str, str]) -> str:
        """Cluster authenticated requests by a one-way fingerprint."""
        authentication = auth_headers(headers)
        if not authentication:
            return ""
        material = json.dumps(authentication, sort_keys=True)
        fingerprint = hashlib.sha256(material.encode()).hexdigest()[:16]
        for identity in self.identities.values():
            if identity.auth_fingerprint == fingerprint:
                if request_id and not identity.source_request_id:
                    identity.source_request_id = request_id
                return identity.name
        name = f"session-{fingerprint[:8]}"
        self.identities[name] = IdentityRecord(
            name=name,
            source_request_id=request_id,
            role="unknown",
            auth_fingerprint=fingerprint,
        )
        self._record_event("identity_discovered", axis=name, state_changed=True)
        return name

    def _record_event(self, event: str, *, axis: str, state_changed: bool) -> None:
        self.campaign_events.append(
            {
                "timestamp": round(time.time(), 3),
                "event": event,
                "axis": axis,
                "state_changed": state_changed,
                "endpoint_count": len(self.endpoints),
                "identity_count": len(self.identities),
                "hypothesis_count": len(self.hypotheses),
            }
        )
        if len(self.campaign_events) > 500:
            del self.campaign_events[:-500]

    def flush(self) -> None:
        """Persist pending batched observations."""
        with self._lock:
            self._persist()

    def register_identity(
        self,
        *,
        name: str,
        source_request_id: str,
        role: str,
        auth_material: str,
    ) -> IdentityRecord:
        """Register only a fingerprint; secrets remain in Caido's captured request."""
        record = IdentityRecord(
            name=name,
            source_request_id=source_request_id,
            role=role,
            auth_fingerprint=hashlib.sha256(auth_material.encode()).hexdigest()[:16],
        )
        with self._lock:
            for existing_name, existing in list(self.identities.items()):
                if (
                    existing_name.startswith("session-")
                    and existing.auth_fingerprint == record.auth_fingerprint
                    and existing_name != name
                ):
                    for endpoint in self.endpoints.values():
                        endpoint.identities = [
                            name if item == existing_name else item for item in endpoint.identities
                        ]
                    del self.identities[existing_name]
            self.identities[name] = record
            self._record_event("identity_registered", axis=name, state_changed=True)
            self._persist()
        return IdentityRecord.from_dict(record.to_dict())

    def generate_idor_hypotheses(self) -> list[HypothesisRecord]:
        """Generate deterministic IDOR candidates from object-like inputs."""
        generated: list[HypothesisRecord] = []
        with self._lock:
            if len(self.identities) < 2:
                return []
            existing_keys = {
                (
                    item.endpoint_key,
                    item.source_request_id,
                    item.parameter_location,
                    item.parameter_name,
                    item.owner_identity,
                )
                for item in self.hypotheses.values()
                if item.hypothesis_type == "horizontal_idor"
            }
            for endpoint in self.endpoints.values():
                owner_identities = [name for name in endpoint.identities if name in self.identities]
                if not owner_identities or not endpoint.request_ids:
                    continue
                for parameter in endpoint.parameters.values():
                    if parameter.identifier_score < 0.65:
                        continue
                    for owner_identity in owner_identities:
                        source_request_id = self.identities[owner_identity].source_request_id
                        if source_request_id not in endpoint.request_ids:
                            source_request_id = endpoint.request_ids[0]
                        dedupe_key = (
                            endpoint.key,
                            source_request_id,
                            parameter.location,
                            parameter.name,
                            owner_identity,
                        )
                        if dedupe_key in existing_keys:
                            continue
                        priority = min(
                            1.0,
                            parameter.identifier_score
                            + (0.08 if endpoint.method == "GET" else 0.04),
                        )
                        record = HypothesisRecord(
                            hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
                            hypothesis_type="horizontal_idor",
                            category="access_control",
                            endpoint_key=endpoint.key,
                            source_request_id=source_request_id,
                            owner_identity=owner_identity,
                            parameter_name=parameter.name,
                            parameter_location=parameter.location,
                            sample_value=parameter.sample_value,
                            value_kind=parameter.value_kind,
                            oracle=(
                                "owner/alternate-identity/anonymous/negative-control differential"
                            ),
                            priority=round(priority, 3),
                            rationale=[
                                "Object-like identifier observed in authenticated traffic",
                                f"Identifier confidence {parameter.identifier_score:.2f}",
                                "At least two test identities are available",
                            ],
                        )
                        self.hypotheses[record.hypothesis_id] = record
                        self._record_event(
                            "hypothesis_generated",
                            axis=f"horizontal_idor:{endpoint.key}:{parameter.name}",
                            state_changed=True,
                        )
                        existing_keys.add(dedupe_key)
                        generated.append(HypothesisRecord.from_dict(record.to_dict()))
            self._persist()
        return sorted(generated, key=lambda item: item.priority, reverse=True)

    def generate_bfla_hypotheses(self) -> list[HypothesisRecord]:
        """Generate vertical/function-level authorization candidates."""
        generated: list[HypothesisRecord] = []
        with self._lock:
            if len(self.identities) < 2:
                return []
            existing = {
                (item.endpoint_key, item.source_request_id, item.owner_identity)
                for item in self.hypotheses.values()
                if item.hypothesis_type == "vertical_authorization"
            }
            for endpoint in self.endpoints.values():
                privileged_route = "privileged_route" in endpoint.workflow_hints
                owners = [
                    name
                    for name in endpoint.identities
                    if name in self.identities
                    and (
                        self.identities[name].role.lower() in _PRIVILEGED_ROLES or privileged_route
                    )
                ]
                for owner in owners:
                    source_request_id = endpoint.request_ids[0] if endpoint.request_ids else ""
                    if not source_request_id:
                        continue
                    key = (endpoint.key, source_request_id, owner)
                    if key in existing:
                        continue
                    priority = (
                        0.9 if self.identities[owner].role.lower() in _PRIVILEGED_ROLES else 0.78
                    )
                    record = HypothesisRecord(
                        hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
                        hypothesis_type="vertical_authorization",
                        category="access_control",
                        endpoint_key=endpoint.key,
                        source_request_id=source_request_id,
                        owner_identity=owner,
                        parameter_name="__function__",
                        parameter_location="path",
                        sample_value=endpoint.route_template,
                        value_kind="route",
                        oracle="privileged/lower-privileged/anonymous differential",
                        priority=priority,
                        rationale=[
                            "Privileged route or privileged owner identity observed",
                            "At least one alternate test identity is available",
                        ],
                    )
                    self.hypotheses[record.hypothesis_id] = record
                    existing.add(key)
                    generated.append(HypothesisRecord.from_dict(record.to_dict()))
                    self._record_event(
                        "hypothesis_generated",
                        axis=f"vertical_authorization:{endpoint.key}",
                        state_changed=True,
                    )
            self._persist()
        return sorted(generated, key=lambda item: item.priority, reverse=True)

    def generate_mass_assignment_hypotheses(self) -> list[HypothesisRecord]:
        """Generate high-signal unsafe-object-binding candidates."""
        generated: list[HypothesisRecord] = []
        with self._lock:
            existing = {
                (item.endpoint_key, item.source_request_id, item.parameter_name)
                for item in self.hypotheses.values()
                if item.hypothesis_type == "mass_assignment"
            }
            for endpoint in self.endpoints.values():
                if endpoint.method not in {"POST", "PUT", "PATCH"} or not endpoint.request_ids:
                    continue
                if not endpoint.identities:
                    continue
                owner = next((name for name in endpoint.identities if name in self.identities), "")
                if not owner:
                    continue
                observed = {
                    parameter.name: parameter
                    for parameter in endpoint.parameters.values()
                    if parameter.location == "body" and parameter.mutation_score >= 0.65
                }
                candidates: dict[str, tuple[str, float, str]] = {}
                for name in observed:
                    mutation = _MASS_ASSIGNMENT_MUTATIONS.get(name.split(".")[-1], "admin")
                    candidates[name] = (mutation, 0.9, "Privileged field observed in request body")
                if any("json" in item or "form" in item for item in endpoint.content_types):
                    for name, mutation in _MASS_ASSIGNMENT_MUTATIONS.items():
                        candidates.setdefault(
                            name,
                            (
                                mutation,
                                0.66,
                                "Privileged field inferred for state-changing endpoint",
                            ),
                        )
                for name, (mutation, priority, reason) in candidates.items():
                    key = (endpoint.key, endpoint.request_ids[0], name)
                    if key in existing:
                        continue
                    record = HypothesisRecord(
                        hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
                        hypothesis_type="mass_assignment",
                        category="api_security",
                        endpoint_key=endpoint.key,
                        source_request_id=endpoint.request_ids[0],
                        owner_identity=owner,
                        parameter_name=name,
                        parameter_location="body",
                        sample_value=observed[name].sample_value if name in observed else "",
                        value_kind="boolean" if mutation == "true" else "string",
                        oracle="baseline/privileged-field/unknown-field/anonymous differential",
                        priority=priority,
                        mutation_value=mutation,
                        rationale=[reason, "Authenticated state-changing endpoint observed"],
                    )
                    self.hypotheses[record.hypothesis_id] = record
                    existing.add(key)
                    generated.append(HypothesisRecord.from_dict(record.to_dict()))
                    self._record_event(
                        "hypothesis_generated",
                        axis=f"mass_assignment:{endpoint.key}:{name}",
                        state_changed=True,
                    )
            self._persist()
        return sorted(generated, key=lambda item: item.priority, reverse=True)

    def generate_all_hypotheses(self) -> list[HypothesisRecord]:
        generated = self.generate_idor_hypotheses()
        generated.extend(self.generate_bfla_hypotheses())
        generated.extend(self.generate_mass_assignment_hypotheses())
        return sorted(generated, key=lambda item: item.priority, reverse=True)

    def update_hypothesis(
        self,
        hypothesis_id: str,
        *,
        status: HypothesisStatus,
        result: dict[str, Any],
    ) -> HypothesisRecord | None:
        with self._lock:
            hypothesis = self.hypotheses.get(hypothesis_id)
            if hypothesis is None:
                return None
            hypothesis.status = status
            hypothesis.result = result
            self._record_event(
                "hypothesis_updated",
                axis=f"{hypothesis.hypothesis_type}:{hypothesis.endpoint_key}",
                state_changed=status in {"confirmed", "rejected"},
            )
            self._persist()
            return HypothesisRecord.from_dict(hypothesis.to_dict())

    def reconcile_report(
        self,
        *,
        report_id: str,
        endpoint: str,
        method: str,
        assessment: EvidenceAssessment,
    ) -> list[HypothesisRecord]:
        """Promote matching hypotheses only when report evidence is verified.

        The report itself is retained as a scan finding regardless of this
        internal classification. This method only controls detection-campaign
        truth, so an HTTP status differential alone remains inconclusive.
        """
        if not report_id:
            return []
        normalized_method = str(method or "GET").upper()
        normalized_route = normalize_route(endpoint)
        updated: list[HypothesisRecord] = []
        with self._lock:
            self.promoted_findings[report_id] = {
                "report_id": report_id,
                "method": normalized_method,
                "route": normalized_route,
                "evidence": assessment.to_dict(),
                "verified": assessment.level == "verified",
                "updated_at": time.time(),
            }
            for hypothesis in self.hypotheses.values():
                key_parts = hypothesis.endpoint_key.split(" ", 1)
                if len(key_parts) != 2 or key_parts[0].upper() != normalized_method:
                    continue
                hypothesis_route = key_parts[1]
                slash_index = hypothesis_route.find("/")
                if slash_index >= 0:
                    hypothesis_route = hypothesis_route[slash_index:]
                if normalize_route(hypothesis_route) != normalized_route:
                    continue
                status: HypothesisStatus = (
                    "confirmed" if assessment.level == "verified" else "inconclusive"
                )
                hypothesis.status = status
                hypothesis.result = {
                    "report_id": report_id,
                    "evidence_level": assessment.level,
                    "evidence": assessment.to_dict(),
                }
                self._record_event(
                    "report_evidence_reconciled",
                    axis=f"{hypothesis.hypothesis_type}:{hypothesis.endpoint_key}",
                    state_changed=status == "confirmed",
                )
                updated.append(HypothesisRecord.from_dict(hypothesis.to_dict()))
            self._persist()
        return updated

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "endpoints": [item.to_dict() for item in self.endpoints.values()],
                "identities": [item.to_dict() for item in self.identities.values()],
                "hypotheses": [
                    item.to_dict()
                    for item in sorted(
                        self.hypotheses.values(),
                        key=lambda hypothesis: hypothesis.priority,
                        reverse=True,
                    )
                ],
                "promoted_findings": list(self.promoted_findings.values()),
                "campaign_health": self.campaign_health(),
            }

    def campaign_health(self) -> dict[str, Any]:
        """Return deterministic progress and stagnation signals."""
        with self._lock:
            recent = self.campaign_events[-12:]
            no_growth_streak = 0
            for event in reversed(recent):
                if event.get("state_changed"):
                    break
                no_growth_streak += 1
            axes = [str(event.get("axis", "")) for event in recent if event.get("axis")]
            dominant_axis_count = max((axes.count(axis) for axis in set(axes)), default=0)
            axis_lock_in = len(axes) >= 6 and dominant_axis_count / len(axes) >= 0.67
            queued = [
                item for item in self.hypotheses.values() if item.status in {"queued", "running"}
            ]
            recommendation = "continue"
            competing_hypotheses: list[dict[str, str]] = []
            if len(self.identities) < 2:
                recommendation = "acquire_or_create_second_identity"
                competing_hypotheses = [
                    {
                        "explanation": "Only public or unauthenticated traffic has been captured",
                        "probe": "Exercise login or registration and ingest the resulting request",
                    },
                    {
                        "explanation": "Authentication uses an unrecognized custom mechanism",
                        "probe": (
                            "Compare pre-login and post-login headers/cookies and register manually"
                        ),
                    },
                ]
            elif no_growth_streak >= 5 or axis_lock_in:
                recommendation = "switch_attack_axis_and_run_disambiguating_probe"
                competing_hypotheses = [
                    {
                        "explanation": "The current endpoint or payload family is exhausted",
                        "probe": "Enumerate a new route family or HTTP method",
                    },
                    {
                        "explanation": "A prerequisite workflow or identity is missing",
                        "probe": "Complete the surrounding UI workflow with another identity",
                    },
                ]
            elif queued:
                recommendation = "execute_ranked_hypotheses"
                competing_hypotheses = [
                    {
                        "explanation": "The highest-ranked authorization hypothesis is exploitable",
                        "probe": "Run its full controlled replay sequence",
                    },
                    {
                        "explanation": "The observed difference is expected authorization behavior",
                        "probe": (
                            "Compare owner, alternate identity, anonymous, and negative controls"
                        ),
                    },
                ]
            return {
                "endpoint_count": len(self.endpoints),
                "identity_count": len(self.identities),
                "hypothesis_counts": {
                    status: sum(1 for item in self.hypotheses.values() if item.status == status)
                    for status in ("queued", "running", "confirmed", "rejected", "inconclusive")
                },
                "verified_findings": sum(
                    bool(item.get("verified")) for item in self.promoted_findings.values()
                ),
                "high_priority_open": sum(
                    item.status in {"queued", "running"} and item.priority >= 0.75
                    for item in self.hypotheses.values()
                ),
                "no_growth_streak": no_growth_streak,
                "axis_lock_in": axis_lock_in,
                "recommendation": recommendation,
                "competing_hypotheses": competing_hypotheses,
            }


def get_detection_store(ctx: Any) -> DetectionStore:
    raw = getattr(ctx, "context", ctx)
    inner = raw if isinstance(raw, dict) else {}
    store = inner.get("_detection_store")
    if not isinstance(store, DetectionStore):
        store = DetectionStore()
        inner["_detection_store"] = store
    return store
