"""Serializable models used by the vulnerability detection pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ParameterLocation = Literal["path", "query", "body"]
HypothesisStatus = Literal["queued", "running", "confirmed", "rejected", "inconclusive"]


@dataclass(slots=True)
class ParameterCandidate:
    """An input that may cross an authorization or trust boundary."""

    name: str
    location: ParameterLocation
    sample_value: str
    value_kind: str
    identifier_score: float
    mutation_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ParameterCandidate:
        return cls(
            name=str(value["name"]),
            location=value["location"],
            sample_value=str(value.get("sample_value", "")),
            value_kind=str(value.get("value_kind", "string")),
            identifier_score=float(value.get("identifier_score", 0.0)),
            mutation_score=float(value.get("mutation_score", 0.0)),
        )


@dataclass(slots=True)
class EndpointRecord:
    """Canonical endpoint plus observations from captured traffic."""

    key: str
    method: str
    host: str
    route_template: str
    parameters: dict[str, ParameterCandidate] = field(default_factory=dict)
    request_ids: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    workflow_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["parameters"] = {
            key: parameter.to_dict() for key, parameter in self.parameters.items()
        }
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EndpointRecord:
        return cls(
            key=str(value["key"]),
            method=str(value.get("method", "GET")),
            host=str(value.get("host", "")),
            route_template=str(value.get("route_template", "/")),
            parameters={
                str(key): ParameterCandidate.from_dict(parameter)
                for key, parameter in value.get("parameters", {}).items()
                if isinstance(parameter, dict)
            },
            request_ids=[str(item) for item in value.get("request_ids", [])],
            identities=[str(item) for item in value.get("identities", [])],
            status_codes=[int(item) for item in value.get("status_codes", [])],
            content_types=[str(item) for item in value.get("content_types", [])],
            workflow_hints=[str(item) for item in value.get("workflow_hints", [])],
        )


@dataclass(slots=True)
class IdentityRecord:
    """A named principal represented by an authenticated captured request."""

    name: str
    source_request_id: str
    role: str = "user"
    auth_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> IdentityRecord:
        return cls(
            name=str(value["name"]),
            source_request_id=str(value["source_request_id"]),
            role=str(value.get("role", "user")),
            auth_fingerprint=str(value.get("auth_fingerprint", "")),
        )


@dataclass(slots=True)
class HypothesisRecord:
    """A testable security hypothesis with explicit preconditions and oracle."""

    hypothesis_id: str
    hypothesis_type: str
    category: str
    endpoint_key: str
    source_request_id: str
    owner_identity: str
    parameter_name: str
    parameter_location: ParameterLocation
    sample_value: str
    value_kind: str
    oracle: str
    priority: float
    mutation_value: str = ""
    rationale: list[str] = field(default_factory=list)
    status: HypothesisStatus = "queued"
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> HypothesisRecord:
        return cls(
            hypothesis_id=str(value["hypothesis_id"]),
            hypothesis_type=str(value["hypothesis_type"]),
            category=str(value["category"]),
            endpoint_key=str(value["endpoint_key"]),
            source_request_id=str(value["source_request_id"]),
            owner_identity=str(value.get("owner_identity", "")),
            parameter_name=str(value["parameter_name"]),
            parameter_location=value["parameter_location"],
            sample_value=str(value.get("sample_value", "")),
            value_kind=str(value.get("value_kind", "string")),
            oracle=str(value.get("oracle", "response-differential")),
            priority=float(value.get("priority", 0.0)),
            mutation_value=str(value.get("mutation_value", "")),
            rationale=[str(item) for item in value.get("rationale", [])],
            status=value.get("status", "queued"),
            result=dict(value.get("result", {})),
        )


@dataclass(slots=True)
class DetectionSignal:
    """Compact semantic comparison returned to the agent and validator."""

    classification: str
    confidence: float
    confirmed: bool
    reasons: list[str]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
