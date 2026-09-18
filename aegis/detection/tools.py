"""Agent tools for attack-surface inventory and IDOR detection."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from agents import RunContextWrapper, function_tool

from aegis.detection.benchmark import get_benchmark_recorder
from aegis.detection.comparator import (
    evaluate_function_authorization,
    evaluate_idor,
    evaluate_mass_assignment,
)
from aegis.detection.extractor import auth_headers, content_type
from aegis.detection.store import get_detection_store
from aegis.tools.enforcement.tracker import get_tracker
from aegis.tools.proxy import caido_api


_IDENTITY_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")


if TYPE_CHECKING:
    from aegis.detection.models import HypothesisRecord, HypothesisStatus


def _ctx_client(ctx: RunContextWrapper) -> Any:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("caido_client")


def _json_result(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _response_content_type(response: dict[str, Any] | None) -> str:
    if not response:
        return ""
    headers = response.get("headers", {})
    return content_type(headers) if isinstance(headers, dict) else ""


def _observe_result(
    ctx: RunContextWrapper,
    *,
    request_id: str,
    result: Any,
    identity_name: str = "",
) -> dict[str, Any]:
    request = result.request
    raw = request.raw
    if raw is None:
        raise ValueError(f"Captured request {request_id} has no raw request")
    components = caido_api.parse_raw_request(raw.decode("utf-8", errors="replace"))
    host = components["headers"].get("Host") or request.host
    response = caido_api.parse_raw_response(
        result.response.raw if result.response is not None else None
    )
    endpoint = get_detection_store(ctx).observe_request(
        request_id=request_id,
        method=components["method"],
        host=host,
        url_path=components["url_path"],
        headers=components["headers"],
        body=components["body"],
        identity_name=identity_name,
        status_code=response.get("status_code") if response else None,
        response_content_type=_response_content_type(response),
    )
    return endpoint.to_dict()


@function_tool(timeout=60, strict_mode=False)
async def observe_request_for_detection(
    ctx: RunContextWrapper,
    request_id: str,
    identity_name: str = "",
) -> str:
    """Add one captured HTTP exchange to the shared attack-surface model.

    Use ``identity_name`` when the request belongs to a registered principal.
    The extractor records route templates and parameter metadata, not session
    secrets or full response bodies.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _json_result({"success": False, "error": "Caido client unavailable"})
    store = get_detection_store(ctx)
    if identity_name and identity_name not in store.identities:
        return _json_result(
            {"success": False, "error": f"Identity '{identity_name}' is not registered"}
        )
    try:
        result = await caido_api.get_request_with_client(client, request_id, part="request")
        if result is None:
            return _json_result({"success": False, "error": f"Request {request_id} not found"})
        endpoint = _observe_result(
            ctx,
            request_id=request_id,
            result=result,
            identity_name=identity_name,
        )
        return _json_result({"success": True, "endpoint": endpoint})
    except Exception as exc:  # noqa: BLE001 - tool errors are model-visible.
        return _json_result({"success": False, "error": f"Observation failed: {exc}"})


@function_tool(timeout=60, strict_mode=False)
async def register_test_identity(
    ctx: RunContextWrapper,
    name: str,
    request_id: str,
    role: str = "user",
) -> str:
    """Register a named principal from an authenticated captured request.

    Only the Caido request id and a fingerprint are persisted. Cookies and
    authorization values remain in Caido and are fetched when a replay runs.
    Use the reserved name ``anonymous`` for an unauthenticated request.
    """
    if not _IDENTITY_NAME_RE.fullmatch(name):
        return _json_result(
            {
                "success": False,
                "error": (
                    "Identity name must start with a letter and contain only "
                    "letters, numbers, _ or -"
                ),
            }
        )
    client = _ctx_client(ctx)
    if client is None:
        return _json_result({"success": False, "error": "Caido client unavailable"})
    try:
        result = await caido_api.get_request_with_client(client, request_id, part="request")
        if result is None or result.request.raw is None:
            return _json_result({"success": False, "error": f"Request {request_id} not found"})
        components = caido_api.parse_raw_request(
            result.request.raw.decode("utf-8", errors="replace")
        )
        authentication = auth_headers(components["headers"])
        if name != "anonymous" and not authentication:
            return _json_result(
                {
                    "success": False,
                    "error": "Captured request has no recognized authentication or session headers",
                }
            )
        identity = get_detection_store(ctx).register_identity(
            name=name,
            source_request_id=request_id,
            role=role,
            auth_material=json.dumps(authentication, sort_keys=True),
        )
        endpoint = _observe_result(
            ctx,
            request_id=request_id,
            result=result,
            identity_name=name,
        )
        return _json_result(
            {
                "success": True,
                "identity": identity.to_dict(),
                "observed_endpoint": endpoint["key"],
            }
        )
    except Exception as exc:  # noqa: BLE001 - tool errors are model-visible.
        return _json_result({"success": False, "error": f"Identity registration failed: {exc}"})


@function_tool(timeout=30, strict_mode=False)
async def inspect_detection_state(
    ctx: RunContextWrapper,
    include_completed: bool = True,
) -> str:
    """Inspect endpoints, identities, and ranked vulnerability hypotheses."""
    snapshot = get_detection_store(ctx).snapshot()
    if not include_completed:
        snapshot["hypotheses"] = [
            item
            for item in snapshot["hypotheses"]
            if item.get("status") in {"queued", "running", "inconclusive"}
        ]
    return _json_result({"success": True, **snapshot})


@function_tool(timeout=30, strict_mode=False)
async def generate_idor_hypotheses(ctx: RunContextWrapper) -> str:
    """Generate ranked horizontal-IDOR hypotheses from the shared surface."""
    store = get_detection_store(ctx)
    generated = store.generate_idor_hypotheses()
    return _json_result(
        {
            "success": True,
            "generated_count": len(generated),
            "hypotheses": [item.to_dict() for item in generated],
            "identity_count": len(store.identities),
            "endpoint_count": len(store.endpoints),
        }
    )


@function_tool(timeout=30, strict_mode=False)
async def generate_authorization_hypotheses(ctx: RunContextWrapper) -> str:
    """Generate IDOR, vertical-authorization, and mass-assignment hypotheses."""
    store = get_detection_store(ctx)
    generated = store.generate_all_hypotheses()
    recorder = get_benchmark_recorder(ctx)
    if recorder is not None:
        recorder.mark_stage(
            "hypothesis_generation",
            detail=f"Generated {len(generated)} new authorization hypotheses",
        )
        recorder.update_metrics(store.campaign_health())
    return _json_result(
        {
            "success": True,
            "generated_count": len(generated),
            "hypotheses": [item.to_dict() for item in generated],
            "campaign_health": store.campaign_health(),
        }
    )


@function_tool(timeout=30, strict_mode=False)
async def inspect_campaign_health(ctx: RunContextWrapper) -> str:
    """Inspect progress, open work, stagnation, and the recommended next action."""
    return _json_result(
        {
            "success": True,
            "campaign_health": get_detection_store(ctx).campaign_health(),
        }
    )


def _identity_headers(components: dict[str, Any]) -> dict[str, str]:
    return auth_headers(components["headers"])


def _apply_identity(
    headers: dict[str, str],
    replacement: dict[str, str],
) -> dict[str, str]:
    replacement_names = {name.lower() for name in replacement}
    auth_names = {name.lower() for name in auth_headers(headers)}
    updated = {
        key: value
        for key, value in headers.items()
        if key.lower() not in auth_names or key.lower() in replacement_names
    }
    for key in list(updated):
        if key.lower() in replacement_names:
            del updated[key]
    updated.update(replacement)
    return updated


def _negative_value(sample: str, value_kind: str) -> str:
    if value_kind == "integer":
        return str(int(sample) + 1_000_003)
    if value_kind == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if value_kind == "hex":
        replacement = "f" * max(8, len(sample))
        return replacement if replacement.lower() != sample.lower() else "e" * len(replacement)
    return f"{sample}-aegis-missing"


def _replace_json_value(value: Any, path: str, replacement: str) -> Any:
    """Replace a flattened dot path; arrays are supported by best effort."""
    parts = [part for part in re.split(r"\.|\[\d+\]", path) if part]
    current = value
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return value
        current = current[part]
    if parts and isinstance(current, dict) and parts[-1] in current:
        original = current[parts[-1]]
        if isinstance(original, int) and replacement.lstrip("-").isdigit():
            current[parts[-1]] = int(replacement)
        else:
            current[parts[-1]] = replacement
    return value


def _negative_variant(
    components: dict[str, Any],
    full_url: str,
    hypothesis: HypothesisRecord,
) -> dict[str, Any]:
    replacement = _negative_value(hypothesis.sample_value, hypothesis.value_kind)
    variant = {
        "method": components["method"],
        "url": full_url,
        "headers": dict(components["headers"]),
        "body": components["body"],
    }
    if hypothesis.parameter_location == "query":
        parsed = urlparse(full_url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[hypothesis.parameter_name] = replacement
        variant["url"] = urlunparse(parsed._replace(query=urlencode(query)))
    elif hypothesis.parameter_location == "path":
        parsed = urlparse(full_url)
        path = parsed.path.replace(hypothesis.sample_value, replacement, 1)
        variant["url"] = urlunparse(parsed._replace(path=path))
    elif hypothesis.parameter_location == "body":
        request_type = content_type(components["headers"]).lower()
        if "json" in request_type:
            parsed_body = json.loads(components["body"])
            variant["body"] = json.dumps(
                _replace_json_value(parsed_body, hypothesis.parameter_name, replacement),
                separators=(",", ":"),
            )
        elif "application/x-www-form-urlencoded" in request_type:
            fields = dict(parse_qsl(components["body"], keep_blank_values=True))
            fields[hypothesis.parameter_name] = replacement
            variant["body"] = urlencode(fields)
    return variant


async def _send_variant(client: Any, variant: dict[str, Any]) -> dict[str, Any]:
    connection, raw = caido_api.build_raw_request(
        method=variant["method"],
        url=variant["url"],
        headers=variant["headers"],
        body=variant["body"],
    )
    replay = await caido_api.replay_send_raw(client, raw=raw, connection=connection)
    return {
        "session_id": replay["session_id"],
        "status": replay["status"],
        "error": replay.get("error"),
        "response": caido_api.parse_raw_response(replay.get("response_raw")),
    }


async def _run_idor_sequence(
    client: Any,
    owner_variant: dict[str, Any],
    attacker_variant: dict[str, Any],
    negative_variant: dict[str, Any],
    anonymous_variant: dict[str, Any],
) -> dict[str, Any]:
    owner = await _send_variant(client, owner_variant)
    attacker = await _send_variant(client, attacker_variant)
    negative = await _send_variant(client, negative_variant)
    anonymous = await _send_variant(client, anonymous_variant)
    signal = evaluate_idor(
        owner["response"],
        attacker["response"],
        negative["response"],
        anonymous["response"],
    )
    return {
        "owner": owner,
        "attacker": attacker,
        "negative": negative,
        "anonymous": anonymous,
        "signal": signal.to_dict(),
    }


def _compact_sequence(sequence: dict[str, Any]) -> dict[str, Any]:
    return {
        "owner": {
            "session_id": sequence["owner"]["session_id"],
            "status": sequence["owner"]["status"],
            "status_code": (sequence["owner"]["response"] or {}).get("status_code"),
        },
        "attacker": {
            "session_id": sequence["attacker"]["session_id"],
            "status": sequence["attacker"]["status"],
            "status_code": (sequence["attacker"]["response"] or {}).get("status_code"),
        },
        "negative": {
            "session_id": sequence["negative"]["session_id"],
            "status": sequence["negative"]["status"],
            "status_code": (sequence["negative"]["response"] or {}).get("status_code"),
        },
        "anonymous": {
            "session_id": sequence["anonymous"]["session_id"],
            "status": sequence["anonymous"]["status"],
            "status_code": (sequence["anonymous"]["response"] or {}).get("status_code"),
        },
        "signal": sequence["signal"],
    }


async def _execute_idor_hypothesis(  # noqa: PLR0911
    ctx: RunContextWrapper,
    hypothesis_id: str,
    test_identity: str,
) -> dict[str, Any]:
    """Execute and independently repeat an IDOR hypothesis.

    The detector performs owner, alternate-identity, anonymous, and
    nonexistent-object probes. A probable result is repeated once and must
    confirm twice before the hypothesis is marked confirmed.
    """
    client = _ctx_client(ctx)
    if client is None:
        return {"success": False, "error": "Caido client unavailable"}
    store = get_detection_store(ctx)
    hypothesis = store.hypotheses.get(hypothesis_id)
    if hypothesis is None:
        return {"success": False, "error": "Hypothesis not found"}
    identity = store.identities.get(test_identity)
    if identity is None:
        return {"success": False, "error": "Test identity not found"}
    if test_identity == hypothesis.owner_identity:
        return {"success": False, "error": "Test identity must differ from owner identity"}

    try:
        store.update_hypothesis(hypothesis_id, status="running", result={})
        source = await caido_api.get_request_with_client(
            client, hypothesis.source_request_id, part="request"
        )
        identity_source = await caido_api.get_request_with_client(
            client, identity.source_request_id, part="request"
        )
        if (
            source is None
            or source.request.raw is None
            or identity_source is None
            or identity_source.request.raw is None
        ):
            error = "Owner or test-identity source request is unavailable"
            store.update_hypothesis(
                hypothesis_id,
                status="inconclusive",
                result={"error": error},
            )
            return {"success": False, "error": error}

        owner_components = caido_api.parse_raw_request(
            source.request.raw.decode("utf-8", errors="replace")
        )
        identity_components = caido_api.parse_raw_request(
            identity_source.request.raw.decode("utf-8", errors="replace")
        )
        full_url = caido_api.full_url_from_components(source.request, owner_components, {})
        owner_variant = {
            "method": owner_components["method"],
            "url": full_url,
            "headers": dict(owner_components["headers"]),
            "body": owner_components["body"],
        }
        attacker_variant = {
            **owner_variant,
            "headers": _apply_identity(
                owner_components["headers"],
                _identity_headers(identity_components),
            ),
        }
        negative_variant = _negative_variant(owner_components, full_url, hypothesis)
        negative_variant["headers"] = dict(attacker_variant["headers"])
        anonymous_variant = {
            **owner_variant,
            "headers": _apply_identity(owner_components["headers"], {}),
        }

        first = await _run_idor_sequence(
            client,
            owner_variant,
            attacker_variant,
            negative_variant,
            anonymous_variant,
        )
        sequences = [first]
        if first["signal"]["confirmed"]:
            sequences.append(
                await _run_idor_sequence(
                    client,
                    owner_variant,
                    attacker_variant,
                    negative_variant,
                    anonymous_variant,
                )
            )
        confirmed = len(sequences) == 2 and all(
            sequence["signal"]["confirmed"] for sequence in sequences
        )
        final_status: HypothesisStatus = "confirmed" if confirmed else "rejected"
        compact_sequences = [_compact_sequence(sequence) for sequence in sequences]
        result_payload = {
            "confirmed": confirmed,
            "classification": ("confirmed_horizontal_idor" if confirmed else "idor_not_confirmed"),
            "test_identity": test_identity,
            "sequences": compact_sequences,
        }
        store.update_hypothesis(
            hypothesis_id,
            status=final_status,
            result=result_payload,
        )

        tracker = get_tracker(ctx)
        for sequence in sequences:
            for probe_name in ("owner", "attacker", "negative", "anonymous"):
                probe = sequence[probe_name]
                response = probe["response"]
                is_attacker = probe_name == "attacker"
                tracker.log_test(
                    category="access_control",
                    endpoint=store.endpoints[hypothesis.endpoint_key].route_template,
                    test_type="horizontal IDOR four-control sequence",
                    tool="repeat_request",
                    sub_category="idor",
                    parameter=hypothesis.parameter_name,
                    payload_family=f"idor-{probe_name}",
                    auth_context=(
                        hypothesis.owner_identity
                        if probe_name == "owner"
                        else "anonymous"
                        if probe_name == "anonymous"
                        else test_identity
                    ),
                    oracle=hypothesis.oracle,
                    evidence_ref=f"caido:replay:{probe['session_id']}",
                    status_code=response.get("status_code") if response else None,
                    finding=bool(confirmed and is_attacker),
                    no_vulnerability_observed=bool(response and (not is_attacker or not confirmed)),
                    payload=hypothesis.sample_value,
                )

        return {  # noqa: TRY300
            "success": True,
            "hypothesis_id": hypothesis_id,
            **result_payload,
        }
    except Exception as exc:  # noqa: BLE001 - tool errors are model-visible.
        store.update_hypothesis(
            hypothesis_id,
            status="inconclusive",
            result={"error": str(exc)},
        )
        return {"success": False, "error": f"IDOR execution failed: {exc}"}


@function_tool(timeout=180, strict_mode=False)
async def execute_idor_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    test_identity: str,
) -> str:
    """Execute and independently repeat a four-control horizontal-IDOR test."""
    return _json_result(await _execute_idor_hypothesis(ctx, hypothesis_id, test_identity))


def _base_variant(source: Any, components: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": components["method"],
        "url": caido_api.full_url_from_components(source.request, components, {}),
        "headers": dict(components["headers"]),
        "body": components["body"],
    }


async def _load_source_variant(
    client: Any,
    hypothesis: HypothesisRecord,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source = await caido_api.get_request_with_client(
        client, hypothesis.source_request_id, part="request"
    )
    if source is None or source.request.raw is None:
        raise ValueError("Hypothesis source request is unavailable")
    components = caido_api.parse_raw_request(source.request.raw.decode("utf-8", errors="replace"))
    return components, _base_variant(source, components)


async def _identity_material(client: Any, source_request_id: str) -> dict[str, str]:
    source = await caido_api.get_request_with_client(client, source_request_id, part="request")
    if source is None or source.request.raw is None:
        raise ValueError("Identity source request is unavailable")
    components = caido_api.parse_raw_request(source.request.raw.decode("utf-8", errors="replace"))
    return _identity_headers(components)


async def _execute_bfla_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    test_identity: str,
) -> dict[str, Any]:
    client = _ctx_client(ctx)
    store = get_detection_store(ctx)
    hypothesis = store.hypotheses.get(hypothesis_id)
    identity = store.identities.get(test_identity)
    if client is None:
        return {"success": False, "error": "Caido client unavailable"}
    if hypothesis is None or hypothesis.hypothesis_type != "vertical_authorization":
        return {"success": False, "error": "Vertical-authorization hypothesis not found"}
    if identity is None or test_identity == hypothesis.owner_identity:
        return {"success": False, "error": "A distinct lower-privileged identity is required"}
    try:
        store.update_hypothesis(hypothesis_id, status="running", result={})
        components, owner_variant = await _load_source_variant(client, hypothesis)
        replacement = await _identity_material(client, identity.source_request_id)
        lower_variant = {
            **owner_variant,
            "headers": _apply_identity(components["headers"], replacement),
        }
        anonymous_variant = {
            **owner_variant,
            "headers": _apply_identity(components["headers"], {}),
        }

        async def run_sequence() -> dict[str, Any]:
            owner = await _send_variant(client, owner_variant)
            lower = await _send_variant(client, lower_variant)
            anonymous = await _send_variant(client, anonymous_variant)
            signal = evaluate_function_authorization(
                owner["response"], lower["response"], anonymous["response"]
            )
            return {"owner": owner, "lower": lower, "anonymous": anonymous, "signal": signal}

        first = await run_sequence()
        sequences = [first]
        if first["signal"].confirmed:
            sequences.append(await run_sequence())
        confirmed = len(sequences) == 2 and all(item["signal"].confirmed for item in sequences)
        compact = [
            {
                name: {
                    "session_id": sequence[name]["session_id"],
                    "status_code": (sequence[name]["response"] or {}).get("status_code"),
                }
                for name in ("owner", "lower", "anonymous")
            }
            | {"signal": sequence["signal"].to_dict()}
            for sequence in sequences
        ]
        result = {
            "confirmed": confirmed,
            "classification": (
                "confirmed_broken_function_level_authorization"
                if confirmed
                else "function_authorization_not_confirmed"
            ),
            "test_identity": test_identity,
            "sequences": compact,
        }
        store.update_hypothesis(
            hypothesis_id,
            status="confirmed" if confirmed else "rejected",
            result=result,
        )
        tracker = get_tracker(ctx)
        for sequence in sequences:
            for name in ("owner", "lower", "anonymous"):
                probe = sequence[name]
                response = probe["response"]
                tracker.log_test(
                    category="access_control",
                    endpoint=store.endpoints[hypothesis.endpoint_key].route_template,
                    test_type="vertical authorization three-control sequence",
                    tool="repeat_request",
                    sub_category="bfla",
                    parameter="__function__",
                    payload_family=f"bfla-{name}",
                    auth_context=(
                        hypothesis.owner_identity
                        if name == "owner"
                        else "anonymous"
                        if name == "anonymous"
                        else test_identity
                    ),
                    oracle=hypothesis.oracle,
                    evidence_ref=f"caido:replay:{probe['session_id']}",
                    status_code=response.get("status_code") if response else None,
                    finding=bool(confirmed and name == "lower"),
                    no_vulnerability_observed=bool(response and (name != "lower" or not confirmed)),
                )
        return {  # noqa: TRY300
            "success": True,
            "hypothesis_id": hypothesis_id,
            **result,
        }
    except Exception as exc:  # noqa: BLE001
        store.update_hypothesis(hypothesis_id, status="inconclusive", result={"error": str(exc)})
        return {"success": False, "error": f"Authorization execution failed: {exc}"}


def _coerce_mutation_value(value: str) -> Any:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def _body_field_variant(
    base: dict[str, Any],
    components: dict[str, Any],
    field_name: str,
    value: str,
) -> dict[str, Any]:
    variant = {**base, "headers": dict(base["headers"])}
    request_type = content_type(components["headers"]).lower()
    if "json" in request_type:
        parsed = json.loads(components["body"] or "{}")
        if not isinstance(parsed, dict):
            raise ValueError("Mass-assignment JSON body must be an object")
        parsed[field_name] = _coerce_mutation_value(value)
        variant["body"] = json.dumps(parsed, separators=(",", ":"))
    elif "application/x-www-form-urlencoded" in request_type:
        fields = dict(parse_qsl(components["body"], keep_blank_values=True))
        fields[field_name] = value
        variant["body"] = urlencode(fields)
    else:
        raise ValueError("Mass-assignment testing requires a JSON or form request body")
    return variant


async def _execute_mass_assignment_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
) -> dict[str, Any]:
    client = _ctx_client(ctx)
    store = get_detection_store(ctx)
    hypothesis = store.hypotheses.get(hypothesis_id)
    if client is None:
        return {"success": False, "error": "Caido client unavailable"}
    if hypothesis is None or hypothesis.hypothesis_type != "mass_assignment":
        return {"success": False, "error": "Mass-assignment hypothesis not found"}
    try:
        store.update_hypothesis(hypothesis_id, status="running", result={})
        components, baseline_variant = await _load_source_variant(client, hypothesis)
        mutated_variant = _body_field_variant(
            baseline_variant,
            components,
            hypothesis.parameter_name,
            hypothesis.mutation_value,
        )
        control_variant = _body_field_variant(
            baseline_variant,
            components,
            "__aegis_unknown_field__",
            "control",
        )
        anonymous_variant = {
            **mutated_variant,
            "headers": _apply_identity(components["headers"], {}),
        }

        async def run_sequence() -> dict[str, Any]:
            baseline = await _send_variant(client, baseline_variant)
            mutated = await _send_variant(client, mutated_variant)
            control = await _send_variant(client, control_variant)
            anonymous = await _send_variant(client, anonymous_variant)
            signal = evaluate_mass_assignment(
                baseline["response"],
                mutated["response"],
                control["response"],
                anonymous["response"],
                field_name=hypothesis.parameter_name,
                mutation_value=hypothesis.mutation_value,
            )
            return {
                "baseline": baseline,
                "mutated": mutated,
                "control": control,
                "anonymous": anonymous,
                "signal": signal,
            }

        first = await run_sequence()
        sequences = [first]
        if first["signal"].confirmed:
            sequences.append(await run_sequence())
        confirmed = len(sequences) == 2 and all(item["signal"].confirmed for item in sequences)
        compact = [
            {
                name: {
                    "session_id": sequence[name]["session_id"],
                    "status_code": (sequence[name]["response"] or {}).get("status_code"),
                }
                for name in ("baseline", "mutated", "control", "anonymous")
            }
            | {"signal": sequence["signal"].to_dict()}
            for sequence in sequences
        ]
        result = {
            "confirmed": confirmed,
            "classification": (
                "confirmed_mass_assignment" if confirmed else "mass_assignment_not_confirmed"
            ),
            "sequences": compact,
        }
        store.update_hypothesis(
            hypothesis_id,
            status="confirmed" if confirmed else "rejected",
            result=result,
        )
        tracker = get_tracker(ctx)
        for sequence in sequences:
            for name in ("baseline", "mutated", "control", "anonymous"):
                probe = sequence[name]
                response = probe["response"]
                tracker.log_test(
                    category="api_security",
                    endpoint=store.endpoints[hypothesis.endpoint_key].route_template,
                    test_type="mass assignment four-control sequence",
                    tool="repeat_request",
                    sub_category="mass_assignment",
                    parameter=hypothesis.parameter_name,
                    payload_family=f"mass-assignment-{name}",
                    auth_context="anonymous" if name == "anonymous" else hypothesis.owner_identity,
                    oracle=hypothesis.oracle,
                    evidence_ref=f"caido:replay:{probe['session_id']}",
                    status_code=response.get("status_code") if response else None,
                    finding=bool(confirmed and name == "mutated"),
                    no_vulnerability_observed=bool(
                        response and (name != "mutated" or not confirmed)
                    ),
                    payload=hypothesis.mutation_value,
                )
        return {  # noqa: TRY300
            "success": True,
            "hypothesis_id": hypothesis_id,
            **result,
        }
    except Exception as exc:  # noqa: BLE001
        store.update_hypothesis(hypothesis_id, status="inconclusive", result={"error": str(exc)})
        return {"success": False, "error": f"Mass-assignment execution failed: {exc}"}


@function_tool(timeout=180, strict_mode=False)
async def execute_authorization_hypothesis(
    ctx: RunContextWrapper,
    hypothesis_id: str,
    test_identity: str = "",
) -> str:
    """Execute any supported authorization hypothesis with its required controls."""
    hypothesis = get_detection_store(ctx).hypotheses.get(hypothesis_id)
    if hypothesis is None:
        return _json_result({"success": False, "error": "Hypothesis not found"})
    if hypothesis.hypothesis_type == "horizontal_idor":
        if not test_identity:
            return _json_result({"success": False, "error": "test_identity is required"})
        result = await _execute_idor_hypothesis(ctx, hypothesis_id, test_identity)
    elif hypothesis.hypothesis_type == "vertical_authorization":
        if not test_identity:
            return _json_result({"success": False, "error": "test_identity is required"})
        result = await _execute_bfla_hypothesis(ctx, hypothesis_id, test_identity)
    elif hypothesis.hypothesis_type == "mass_assignment":
        result = await _execute_mass_assignment_hypothesis(ctx, hypothesis_id)
    else:
        result = {"success": False, "error": "Unsupported hypothesis type"}
    return _json_result(result)


def _alternate_identity(store: Any, hypothesis: HypothesisRecord) -> str:
    candidates = [
        item
        for item in store.identities.values()
        if item.name not in {hypothesis.owner_identity, "anonymous"}
    ]
    if hypothesis.hypothesis_type == "vertical_authorization":
        candidates.sort(
            key=lambda item: (
                item.role.lower() in {"admin", "administrator", "privileged", "staff", "superuser"}
            )
        )
    return candidates[0].name if candidates else ""


@function_tool(timeout=900, strict_mode=False)
async def run_detection_campaign(
    ctx: RunContextWrapper,
    max_hypotheses: int = 8,
    minimum_priority: float = 0.65,
) -> str:
    """Generate and drain the ranked authorization hypothesis queue automatically."""
    if max_hypotheses < 1 or max_hypotheses > 25:
        return _json_result({"success": False, "error": "max_hypotheses must be 1-25"})
    if minimum_priority < 0.0 or minimum_priority > 1.0:
        return _json_result({"success": False, "error": "minimum_priority must be 0-1"})
    store = get_detection_store(ctx)
    store.generate_all_hypotheses()
    queued = sorted(
        (
            item
            for item in store.hypotheses.values()
            if item.status in {"queued", "inconclusive"} and item.priority >= minimum_priority
        ),
        key=lambda item: item.priority,
        reverse=True,
    )[:max_hypotheses]
    recorder = get_benchmark_recorder(ctx)
    if recorder is not None:
        recorder.mark_stage("exploitation", detail=f"Executing {len(queued)} hypotheses")
    results: list[dict[str, Any]] = []
    for hypothesis in queued:
        if hypothesis.hypothesis_type == "mass_assignment":
            result = await _execute_mass_assignment_hypothesis(ctx, hypothesis.hypothesis_id)
        else:
            test_identity = _alternate_identity(store, hypothesis)
            if not test_identity:
                result = {
                    "success": False,
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "error": "No alternate identity available",
                }
                store.update_hypothesis(
                    hypothesis.hypothesis_id,
                    status="inconclusive",
                    result={"error": result["error"]},
                )
            elif hypothesis.hypothesis_type == "horizontal_idor":
                result = await _execute_idor_hypothesis(
                    ctx, hypothesis.hypothesis_id, test_identity
                )
            else:
                result = await _execute_bfla_hypothesis(
                    ctx, hypothesis.hypothesis_id, test_identity
                )
        results.append(result)
    confirmed = sum(bool(item.get("confirmed")) for item in results)
    health = store.campaign_health()
    if recorder is not None:
        recorder.mark_stage(
            "validation",
            detail=f"Campaign confirmed {confirmed} of {len(results)} executed hypotheses",
        )
        recorder.update_metrics({**health, "campaign_confirmed": confirmed})
    return _json_result(
        {
            "success": True,
            "executed_count": len(results),
            "confirmed_count": confirmed,
            "results": results,
            "campaign_health": health,
        }
    )


@function_tool(timeout=180, strict_mode=False)
async def bootstrap_detection_identities(
    ctx: RunContextWrapper,
    request_ids: list[str],
) -> str:
    """Batch-ingest captured requests and automatically cluster authenticated sessions."""
    client = _ctx_client(ctx)
    if client is None:
        return _json_result({"success": False, "error": "Caido client unavailable"})
    if not request_ids or len(request_ids) > 100:
        return _json_result({"success": False, "error": "Provide 1-100 request ids"})
    observed = 0
    errors: list[str] = []
    for request_id in dict.fromkeys(request_ids):
        try:
            result = await caido_api.get_request_with_client(client, request_id, part="request")
            if result is None:
                errors.append(f"{request_id}: not found")
                continue
            _observe_result(ctx, request_id=request_id, result=result)
            observed += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{request_id}: {exc}")
    store = get_detection_store(ctx)
    recorder = get_benchmark_recorder(ctx)
    if recorder is not None:
        recorder.mark_stage(
            "authentication",
            detail=f"Clustered {len(store.identities)} identities from {observed} requests",
        )
    return _json_result(
        {
            "success": observed > 0,
            "observed_count": observed,
            "identities": [item.to_dict() for item in store.identities.values()],
            "workflow_candidates": [
                {"endpoint": item.key, "hints": item.workflow_hints}
                for item in store.endpoints.values()
                if "authentication_flow" in item.workflow_hints
            ],
            "errors": errors,
        }
    )
