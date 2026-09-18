"""Caido proxy host-side @function_tool wrappers around caido_api.py."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
from dataclasses import is_dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from agents import RunContextWrapper, function_tool

from aegis.detection.store import get_detection_store
from aegis.tools.enforcement.minimums import MANDATORY_CATEGORIES
from aegis.tools.enforcement.tracker import get_tracker
from aegis.tools.proxy import caido_api


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from caido_sdk_client import Client

    from aegis.tools.proxy.caido_api import (
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )
else:
    from aegis.tools.proxy.caido_api import (  # noqa: TC001
        RequestPart,
        SitemapDepth,
        SortBy,
        SortOrder,
    )


ScopeAction = Literal["get", "list", "create", "update", "delete"]


def _record_surface_from_result(
    ctx: RunContextWrapper,
    *,
    request_id: str,
    result: Any,
    identity_name: str = "",
    persist: bool = True,
) -> None:
    """Best-effort attack-surface ingestion that never breaks proxy access."""
    try:
        request = result.request
        if request.raw is None:
            return
        components = caido_api.parse_raw_request(request.raw.decode("utf-8", errors="replace"))
        response = caido_api.parse_raw_response(
            result.response.raw if result.response is not None else None
        )
        response_headers = response.get("headers", {}) if response else {}
        response_content_type = next(
            (
                str(value)
                for key, value in response_headers.items()
                if str(key).lower() == "content-type"
            ),
            "",
        )
        host = components["headers"].get("Host") or request.host
        get_detection_store(ctx).observe_request(
            request_id=request_id,
            method=components["method"],
            host=host,
            url_path=components["url_path"],
            headers=components["headers"],
            body=components["body"],
            identity_name=identity_name,
            status_code=response.get("status_code") if response else None,
            response_content_type=response_content_type,
            persist=persist,
        )
    except Exception:  # noqa: BLE001 - surface ingestion must not break proxy tools.
        logger.debug(
            "Could not ingest request %s into detection surface", request_id, exc_info=True
        )


def _ctx_client(ctx: RunContextWrapper) -> Client | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("caido_client")


async def _reconnect_client(ctx: RunContextWrapper) -> Client | None:
    """Reconnect a stale Caido client by creating a fresh connection.

    The bootstrap client's GraphQL WebSocket can go stale over long scans.
    This function creates a new client using the same URL and token,
    then updates the context so subsequent calls use the fresh connection.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    old_client = inner.get("caido_client")
    if old_client is None:
        return None

    # Get the bootstrap URL from context (stored during session creation)
    base_url = inner.get("caido_url")
    if not base_url:
        base_url = caido_api.caido_url()

    try:
        # Close the stale connection
        await old_client.aclose()
    except Exception:  # noqa: BLE001
        pass

    try:
        # Login fresh and create a new client using the bootstrap URL
        from caido_sdk_client import Client as CaidoClient
        from caido_sdk_client import TokenAuthOptions

        # Use the token-based login via the graphql endpoint with the correct URL
        token = await asyncio.to_thread(caido_api._login_as_guest, base_url)
        new_client = CaidoClient(base_url, auth=TokenAuthOptions(token=token))
        await new_client.connect()

        # Select a project (create if needed)
        try:
            projects = await new_client.project.list()
            if projects:
                await new_client.project.select(projects[0].id)
            else:
                from caido_sdk_client.types import CreateProjectOptions

                project = await new_client.project.create(
                    CreateProjectOptions(name="sandbox", temporary=True)
                )
                await new_client.project.select(project.id)
        except Exception:  # noqa: BLE001
            logger.debug("Project selection failed during reconnect, continuing")

        # Update context with fresh client
        inner["caido_client"] = new_client
        logger.info("Caido client reconnected successfully to %s", base_url)
        return new_client

    except Exception as exc:
        logger.warning("Caido client reconnect failed: %s", exc)
        return None


def _is_network_error(exc: Exception) -> bool:
    """Check if an exception is a Caido network/transient error that warrants reconnection."""
    exc_str = str(exc).lower()
    return any(
        pattern in exc_str
        for pattern in [
            "network error",
            "connection",
            "transport",
            "websocket",
            "closed",
            "broken pipe",
            "reset by peer",
            "eof",
            "timeout",
        ]
    )


def _to_tool_json(value: Any) -> Any:
    """Recursively convert SDK dataclasses/Pydantic objects to tool JSON values."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {k: _to_tool_json(v) for k, v in dataclasses.asdict(value).items()}
    if hasattr(value, "model_dump"):
        return _to_tool_json(value.model_dump())
    if isinstance(value, dict):
        return {str(k): _to_tool_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_tool_json(v) for v in value]
    return str(value)


def _no_client() -> str:
    return json.dumps(
        {"success": False, "error": "Caido client not available in run context"},
        ensure_ascii=False,
        default=str,
    )


def _err(name: str, exc: Exception) -> str:
    logger.exception("%s failed", name)
    return json.dumps(
        {"success": False, "error": f"{name} failed: {exc}"},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120)
async def list_requests(
    ctx: RunContextWrapper,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> str:
    """List captured HTTP requests from the Caido proxy with HTTPQL filtering.

    Caido HTTPQL syntax (operators differ by field type):

    - **Integer fields** (``resp.code``, ``req.port``, ``id``,
      ``roundtrip``) — ``eq``, ``gt``, ``gte``, ``lt``, ``lte``, ``ne``.
      Examples: ``resp.code.eq:200``, ``resp.code.gte:400``,
      ``req.port.eq:443``.
    - **Text/byte fields** (``req.method``, ``req.host``, ``req.path``,
      ``req.query``, ``req.ext``, ``req.raw``) — ``regex``, ``cont``
      (substring), ``eq``. Examples: ``req.method.eq:"POST"``,
      ``req.path.cont:"/api/"``, ``req.host.regex:".*\\.example\\.com"``.
    - **Date fields** (``req.created_at``) — ``gt``, ``lt`` with ISO
      timestamps: ``req.created_at.gt:"2024-01-01T00:00:00Z"``.
    - **Combine** with ``AND`` / ``OR``: ``req.method.eq:"POST" AND
      resp.code.gte:400``.
    - **Special**: ``source:intercept`` (only intercepted requests),
      ``preset:"name"``.

    For sitemap-style tree traversal use HTTPQL filters: drill into a
    host with ``req.host.eq:"example.com"`` then narrow paths with
    ``req.path.cont:"/api/"``.

    Pagination is cursor-based. Pass the ``end_cursor`` from the
    ``page_info`` of one call as ``after`` to the next.

    Notes:

    - HTTPQL has **no ``NOT`` operator**. Use the negated form of the
      operator instead: ``ne``, ``ncont``, ``nlike``, ``nregex``
      (e.g. ``req.path.ncont:"/static"`` to exclude static paths).
    - String values **must be quoted**; integer values **must not**.
      ``resp.code.eq:200`` is right; ``resp.code.eq:"200"`` is a parse
      error. Same rule for ``cont`` / ``regex`` strings.
    - A bare quoted string searches both ``req.raw`` and ``resp.raw``,
      handy for sensitive-data sweeps:
      ``"password" OR "secret" OR "api_key"``.

    Args:
        httpql_filter: Caido HTTPQL query (optional).
        first: Number of entries to return (default 50).
        after: Cursor from a previous response's ``page_info.end_cursor``.
        sort_by: One of ``timestamp`` / ``host`` / ``method`` / ``path``
            / ``status_code`` / ``response_time`` / ``response_size``
            / ``source``.
        sort_order: ``asc`` or ``desc``.
        scope_id: Restrict to a Caido scope (managed via ``scope_rules``).
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    for attempt in range(2):
        try:
            connection = await caido_api.list_requests_with_client(
                client,
                httpql_filter=httpql_filter,
                first=first,
                after=after,
                sort_by=sort_by,
                sort_order=sort_order,
                scope_id=scope_id,
            )

            entries = []
            request_ids: list[str] = []
            detection_store = get_detection_store(ctx)
            for edge in connection.edges:
                req = edge.node.request
                resp = edge.node.response
                response_payload: dict[str, Any] | None = None
                if resp is not None:
                    response_payload = {
                        "id": resp.id,
                        "status_code": resp.status_code,
                        "length": resp.length,
                        "created_at": resp.created_at.isoformat(),
                    }
                    if resp.roundtrip_time:
                        response_payload["roundtrip_ms"] = resp.roundtrip_time
                entries.append(
                    {
                        "cursor": edge.cursor,
                        "request": {
                            "id": req.id,
                            "host": req.host,
                            "port": req.port,
                            "method": req.method,
                            "path": req.path,
                            "query": req.query,
                            "is_tls": req.is_tls,
                            "created_at": req.created_at.isoformat(),
                        },
                        "response": response_payload,
                    },
                )
                request_ids.append(str(req.id))
                query = str(req.query or "")
                url_path = str(req.path or "/")
                if query:
                    url_path = f"{url_path}?{query}"
                detection_store.observe_request(
                    request_id=str(req.id),
                    method=str(req.method),
                    host=str(req.host),
                    url_path=url_path,
                    headers={},
                    body="",
                    status_code=resp.status_code if resp is not None else None,
                    persist=False,
                )

            hydration_limit = asyncio.Semaphore(8)

            async def hydrate_request(request_id: str, active_client: Client) -> None:
                async with hydration_limit:
                    try:
                        captured = await caido_api.get_request_with_client(
                            active_client, request_id, part="request"
                        )
                        if captured is not None:
                            _record_surface_from_result(
                                ctx,
                                request_id=request_id,
                                result=captured,
                                persist=False,
                            )
                    except Exception:  # noqa: BLE001 - listing must remain available.
                        logger.debug(
                            "Could not hydrate request %s for detection",
                            request_id,
                            exc_info=True,
                        )

            await asyncio.gather(
                *(hydrate_request(request_id, client) for request_id in request_ids)
            )
            detection_store.flush()

            return json.dumps(
                {
                    "success": True,
                    "entries": entries,
                    "page_info": {
                        "has_next_page": connection.page_info.has_next_page,
                        "has_previous_page": connection.page_info.has_previous_page,
                        "start_cursor": connection.page_info.start_cursor,
                        "end_cursor": connection.page_info.end_cursor,
                    },
                },
                ensure_ascii=False,
                default=str,
            )
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("list_requests", exc)
                continue
            return _err("list_requests", exc)


@function_tool(timeout=60)
async def view_request(
    ctx: RunContextWrapper,
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
    identity_name: str = "",
) -> str:
    """View a captured request or its response, optionally regex-searched.

    Two modes:

    - **With** ``search_pattern`` (compact regex hits) — returns up to 20
      matches with ``before`` / ``after`` context and position. Useful
      for hunting reflected input, leaked URLs, hidden parameters.
    - **Without** ``search_pattern`` (full content with line pagination)
      — returns the page of raw content plus ``has_more`` flag.

    Common search patterns:

    - API endpoints: ``/api/[a-zA-Z0-9._/-]+``
    - URLs: ``https?://[^\\s<>"']+``
    - Query parameters: ``[?&][a-zA-Z0-9_]+=([^&\\s<>"']+)``
    - Specific input reflection: search for the value you submitted.

    Args:
        request_id: Request ID from ``list_requests``.
        part: ``"request"`` or ``"response"``.
        search_pattern: Optional regex; switches the response shape to
            compact hits.
        page: 1-indexed page number (only when no ``search_pattern``).
        page_size: Lines per page.
        identity_name: Optional registered identity associated with the request.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    for attempt in range(2):
        try:
            result = await caido_api.get_request_with_client(client, request_id, part=part)
            if result is None:
                return json.dumps(
                    {"success": False, "error": f"Request {request_id} not found"},
                    ensure_ascii=False,
                    default=str,
                )

            store = get_detection_store(ctx)
            if identity_name and identity_name not in store.identities:
                return json.dumps(
                    {"success": False, "error": f"Identity '{identity_name}' is not registered"},
                    ensure_ascii=False,
                )
            _record_surface_from_result(
                ctx,
                request_id=request_id,
                result=result,
                identity_name=identity_name,
            )

            raw_bytes = (
                result.request.raw
                if part == "request"
                else (result.response.raw if result.response is not None else None)
            )
            if raw_bytes is None:
                return json.dumps(
                    {
                        "success": False,
                        "error": f"No raw {part} for {request_id}",
                    },
                    ensure_ascii=False,
                    default=str,
                )
            content = raw_bytes.decode("utf-8", errors="replace")

            if search_pattern:
                return json.dumps(
                    _format_search_hits(content, search_pattern),
                    ensure_ascii=False,
                    default=str,
                )

            return json.dumps(
                _format_text_page(content, page=page, page_size=page_size),
                ensure_ascii=False,
                default=str,
            )
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("view_request", exc)
                continue
            return _err("view_request", exc)


def _format_search_hits(content: str, pattern: str) -> dict[str, Any]:
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return {"success": False, "error": f"Invalid regex: {exc}"}

    hits = []
    for match in regex.finditer(content):
        start, end = match.span()
        before = content[max(0, start - 40) : start]
        after = content[end : end + 40]
        hits.append(
            {
                "match": match.group(0),
                "position": start,
                "before": before,
                "after": after,
            },
        )
        if len(hits) >= 20:
            break

    return {"success": True, "hits": hits, "total_hits": len(hits)}


def _format_text_page(content: str, *, page: int, page_size: int) -> dict[str, Any]:
    lines = content.splitlines()
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "success": True,
        "content": "\n".join(lines[start:end]),
        "page": page,
        "page_size": page_size,
        "total_lines": len(lines),
        "has_more": end < len(lines),
    }


@function_tool(timeout=120, strict_mode=False)
async def repeat_request(
    ctx: RunContextWrapper,
    request_id: str,
    modifications: dict[str, Any] | None = None,
    category: str | None = None,
    endpoint_template: str = "",
    sub_category: str = "",
    test_type: str = "",
    parameter: str = "",
    payload_family: str = "",
    auth_context: str = "anonymous",
    oracle: str = "response-differential",
    finding: bool = False,
    no_vulnerability_observed: bool = False,
) -> str:
    """Repeat a captured request, optionally patching individual fields.

    The standard pentesting workflow with this tool:

    1. ``agent-browser`` (via ``exec_command``) or live target traffic
       → request gets captured by Caido.
    2. ``list_requests`` → find the request ID you want to manipulate.
    3. ``repeat_request`` → send a modified version (auth-bypass test,
       payload injection, parameter tampering).

    Mirrors the manual "browse → capture → modify → test" flow used in
    real pentesting. Inherits everything from the original request
    (headers, cookies, auth, method, URL) and overlays only the fields
    you specify in ``modifications``.

    Args:
        request_id: ID of the original request (from ``list_requests``).
        modifications: Patch dict. Recognized keys:

            - ``url`` — replace the URL.
            - ``params`` — dict of query-string keys to add/update.
            - ``headers`` — dict of headers to add/update.
            - ``body`` — replace the body string entirely.
            - ``cookies`` — dict of cookies to add/update.
        category: Optional mandatory coverage category. When supplied, this
            replay is added to the shared evidence ledger after it executes.
        endpoint_template: Stable route identity such as ``/users/{id}``.
            Defaults to the original captured URL with its query removed.
        sub_category: Specific weakness family, such as ``idor`` or ``sqli``.
        test_type: Short description of the security hypothesis tested.
        parameter: Input or object reference changed by the probe.
        payload_family: Payload technique rather than the literal payload.
        auth_context: Identity or role used for the replay.
        oracle: Observation used to decide the result.
        finding: Whether the replay confirmed a vulnerability.
        no_vulnerability_observed: Whether it completed without confirming one.
    """
    if category is not None and category not in MANDATORY_CATEGORIES:
        return json.dumps(
            {
                "success": False,
                "error": f"Invalid category: {category}",
                "valid_categories": sorted(MANDATORY_CATEGORIES),
            },
            ensure_ascii=False,
        )
    if category is not None and not test_type.strip():
        return json.dumps(
            {
                "success": False,
                "error": "test_type is required when category is supplied",
            },
            ensure_ascii=False,
        )
    if finding and no_vulnerability_observed:
        return json.dumps(
            {
                "success": False,
                "error": "A replay cannot be both a finding and a negative observation",
            },
            ensure_ascii=False,
        )

    client = _ctx_client(ctx)
    if client is None:
        return _no_client()
    mods = modifications or {}

    for attempt in range(2):
        try:
            result = await caido_api.get_request_with_client(client, request_id, part="request")
            if result is None or result.request.raw is None:
                return json.dumps(
                    {"success": False, "error": f"Request {request_id} not found"},
                    ensure_ascii=False,
                    default=str,
                )

            original = result.request
            detection_store = get_detection_store(ctx)
            observed_identity = auth_context if auth_context in detection_store.identities else ""
            _record_surface_from_result(
                ctx,
                request_id=request_id,
                result=result,
                identity_name=observed_identity,
            )
            raw_str = result.request.raw.decode("utf-8", errors="replace")
            components = caido_api.parse_raw_request(raw_str)
            full_url = caido_api.full_url_from_components(original, components, mods)
            modified = caido_api.apply_modifications(components, mods, full_url)
            connection, raw = caido_api.build_raw_request(
                method=modified["method"],
                url=modified["url"],
                headers=modified["headers"],
                body=modified["body"],
            )
            replay = await caido_api.replay_send_raw(client, raw=raw, connection=connection)
            payload = _format_replay_tool_result(replay)
            if category is not None:
                response = payload.get("response")
                if payload["success"] and isinstance(response, dict):
                    event = get_tracker(ctx).log_test(
                        category=category,
                        endpoint=endpoint_template or full_url,
                        test_type=test_type,
                        tool="repeat_request",
                        sub_category=sub_category,
                        payload=json.dumps(
                            mods,
                            sort_keys=True,
                            ensure_ascii=False,
                            default=str,
                        ),
                        parameter=parameter,
                        payload_family=payload_family,
                        auth_context=auth_context,
                        oracle=oracle,
                        evidence_ref=f"caido:replay:{replay['session_id']}",
                        status_code=response.get("status_code"),
                        finding=finding,
                        no_vulnerability_observed=no_vulnerability_observed,
                    )
                    payload["coverage_event"] = {
                        "event_id": event["event_id"],
                        "created": event["created"],
                        "category": event["category"],
                    }
                else:
                    payload["coverage_error"] = (
                        "Replay did not produce a parseable response and was not counted"
                    )
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("repeat_request", exc)
                continue
            return _err("repeat_request", exc)
    return _err("repeat_request", RuntimeError("Replay attempts exhausted"))


def _format_replay_tool_result(replay: dict[str, Any]) -> dict[str, Any]:
    response = caido_api.parse_raw_response(replay.get("response_raw"))
    payload: dict[str, Any] = {
        "success": replay["status"] == "DONE",
        "status": replay["status"],
        "session_id": replay["session_id"],
        "elapsed_ms": replay["elapsed_ms"],
        "response": response,
    }
    if replay.get("error"):
        payload["error"] = replay["error"]
    return payload


@function_tool(timeout=60)
async def list_sitemap(
    ctx: RunContextWrapper,
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: SitemapDepth = "DIRECT",
    page: int = 1,
) -> str:
    """Browse Caido's hierarchical sitemap of proxied traffic.

    Caido aggregates every captured request into a tree:
    ``DOMAIN`` → ``DIRECTORY`` (path segments) → ``REQUEST`` →
    ``REQUEST_BODY`` / ``REQUEST_QUERY`` (variant per body/query shape).
    Use this to understand the discovered attack surface, locate
    promising directories, and pick endpoints worth deeper testing.

    Workflow:
    - Start with no ``parent_id`` to list root domains (scoped by
      ``scope_id`` if you only care about in-scope hosts).
    - Pick an entry where ``has_descendants=true`` and pass its ``id``
      as ``parent_id`` to drill in. ``depth="DIRECT"`` returns only
      immediate children; ``"ALL"`` flattens the full subtree.
    - Hand any ``id`` to ``view_sitemap_entry`` for the full record
      and recent matching requests.

    Args:
        scope_id: Limit roots to a Caido scope (only used when
            ``parent_id`` is omitted). Manage scopes via ``scope_rules``.
        parent_id: Entry ID to expand; omit for root domains.
        depth: ``"DIRECT"`` (immediate children) or ``"ALL"``
            (recursive subtree). Only meaningful with ``parent_id``.
        page: 1-indexed page (30 entries per page).
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()
    for attempt in range(2):
        try:
            payload = await caido_api.list_sitemap_with_client(
                client,
                scope_id=scope_id,
                parent_id=parent_id,
                depth=depth,
                page=page,
            )
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("list_sitemap", exc)
                continue
            return _err("list_sitemap", exc)


@function_tool(timeout=60)
async def view_sitemap_entry(
    ctx: RunContextWrapper,
    entry_id: str,
) -> str:
    """Get full detail for a sitemap entry plus its recent requests.

    Returns the entry's metadata, the primary request shape
    (method/path/response if any), and the most recent 30 related
    requests that fall under this entry. Pair with ``list_sitemap`` to
    pick the ``entry_id``.

    Args:
        entry_id: ID from ``list_sitemap`` (or any nested entry).
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()
    for attempt in range(2):
        try:
            payload = await caido_api.view_sitemap_entry_with_client(client, entry_id)
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("view_sitemap_entry", exc)
                continue
            return _err("view_sitemap_entry", exc)


@function_tool(timeout=60)
async def scope_rules(
    ctx: RunContextWrapper,
    action: ScopeAction,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> str:
    """CRUD on Caido scope rules (allow/deny patterns).

    Scopes filter which traffic Caido tools see. Use them to focus on a
    target, exclude noisy assets (CDNs, static files), or define a
    bug-bounty allowlist.

    Pattern semantics:

    - Glob wildcards: ``*`` (any), ``?`` (single), ``[abc]`` (one of),
      ``[a-z]`` (range), ``[^abc]`` (none of).
    - **Empty allowlist = allow all domains.**
    - **Denylist always overrides allowlist.**

    Common denylist for noisy static assets:
    ``["*.gif", "*.jpg", "*.png", "*.css", "*.js", "*.ico", "*.svg",
    "*woff*", "*.ttf"]``.

    Each scope has a unique id usable as ``scope_id`` in
    ``list_requests``.

    Args:
        action:

            - ``list`` — return all scopes.
            - ``get`` — single scope by ``scope_id``.
            - ``create`` — needs ``scope_name``, optionally
              ``allowlist`` / ``denylist``.
            - ``update`` — needs ``scope_id`` + ``scope_name``;
              allowlist / denylist replace the previous values.
            - ``delete`` — needs ``scope_id``.

        allowlist: Domain patterns to include (e.g.
            ``["*.example.com", "api.test.com"]``).
        denylist: Patterns to exclude.
        scope_id: Required for ``get`` / ``update`` / ``delete``.
        scope_name: Required for ``create`` / ``update``.
    """
    client = _ctx_client(ctx)
    if client is None:
        return _no_client()

    for attempt in range(2):
        try:
            if action == "list":
                scopes = await caido_api.scope_list(client)
                return json.dumps(
                    {"success": True, "scopes": [_to_tool_json(s) for s in scopes]},
                    ensure_ascii=False,
                    default=str,
                )
            if action == "get":
                if not scope_id:
                    return json.dumps(
                        {"success": False, "error": "Scope_id is required for action='get'"},
                        ensure_ascii=False,
                        default=str,
                    )
                scope = await caido_api.scope_get(client, scope_id)
                return json.dumps(
                    {"success": True, "scope": _to_tool_json(scope)},
                    ensure_ascii=False,
                    default=str,
                )
            if action == "create":
                if not scope_name:
                    return json.dumps(
                        {"success": False, "error": "Scope_name is required for action='create'"},
                        ensure_ascii=False,
                        default=str,
                    )
                scope = await caido_api.scope_create(
                    client, name=scope_name, allowlist=allowlist, denylist=denylist
                )
                return json.dumps(
                    {"success": True, "scope": _to_tool_json(scope)},
                    ensure_ascii=False,
                    default=str,
                )
            if action == "update":
                if not scope_id or not scope_name:
                    return json.dumps(
                        {
                            "success": False,
                            "error": "Scope_id and scope_name are required for action='update'",
                        },
                        ensure_ascii=False,
                        default=str,
                    )
                scope = await caido_api.scope_update(
                    client, scope_id, name=scope_name, allowlist=allowlist, denylist=denylist
                )
                return json.dumps(
                    {"success": True, "scope": _to_tool_json(scope)},
                    ensure_ascii=False,
                    default=str,
                )
            if not scope_id:
                return json.dumps(
                    {"success": False, "error": "Scope_id is required for action='delete'"},
                    ensure_ascii=False,
                    default=str,
                )
            await caido_api.scope_delete(client, scope_id)
            return json.dumps(
                {
                    "success": True,
                    "deleted": scope_id,
                    "message": f"Scope {scope_id} deleted",
                },
                ensure_ascii=False,
                default=str,
            )
        except Exception as exc:  # noqa: BLE001
            if attempt == 0 and _is_network_error(exc):
                logger.info("Caido connection stale, reconnecting (attempt %d)", attempt + 1)
                client = await _reconnect_client(ctx)
                if client is None:
                    return _err("scope_rules", exc)
                continue
            return _err("scope_rules", exc)
