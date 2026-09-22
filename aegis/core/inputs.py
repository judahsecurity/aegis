"""Pure input builders for Aegis scan runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from aegis.config.models import DEFAULT_MODEL_RETRY, model_supports_reasoning


if TYPE_CHECKING:
    from aegis.config.settings import ReasoningEffort


DEFAULT_MAX_TURNS = 500


def build_root_task(scan_config: dict[str, Any]) -> str:
    targets = scan_config.get("targets", []) or []
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""

    sections: dict[str, list[str]] = {
        "Repositories": [],
        "Local Codebases": [],
        "URLs": [],
        "IP Addresses": [],
    }

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            suffix = ", read-only mount" if details.get("mount") else ""
            sections["Local Codebases"].append(f"- {path} (available at: {workspace_path}{suffix})")
        elif ttype == "web_application":
            sections["URLs"].append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {details.get('target_ip', '')}")

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if diff_scope.get("active"):
        parts.append("\n\nScope Constraints:")
        parts.append(
            "- Pull request diff-scope mode is active. Prioritize changed files "
            "and use other files only for context.",
        )
        for repo_scope in diff_scope.get("repos", []) or []:
            label = (
                repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
            )
            changed = repo_scope.get("analyzable_files_count", 0)
            deleted = repo_scope.get("deleted_files_count", 0)
            parts.append(f"- {label}: {changed} changed file(s) in primary scope")
            if deleted:
                parts.append(f"- {label}: {deleted} deleted file(s) are context-only")

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    authorized: list[dict[str, str]] = []
    value_keys = {
        "repository": "target_repo",
        "local_code": "target_path",
        "web_application": "target_url",
        "ip_address": "target_ip",
        "mobile_app": "mobile_app_path",
    }
    mobile_mode = False
    for target in scan_config.get("targets", []) or []:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        key = value_keys.get(ttype)
        value = details.get(key, "") if key is not None else target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        # For mobile apps, include the filename so the agent knows the exact path
        if ttype == "mobile_app" and workspace_path:
            app_path = Path(details.get("mobile_app_path", ""))
            if app_path.name:
                workspace_path = f"{workspace_path}/{app_path.name}"
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )
        if ttype == "mobile_app":
            mobile_mode = True

    ctx: dict[str, Any] = {
        "scope_source": "system_scan_config",
        "authorization_source": "aegis_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
    }
    if mobile_mode:
        ctx["mobile_mode"] = True
    if scan_config.get("internal_mode"):
        ctx["internal_mode"] = True
    return ctx


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
) -> ModelSettings:
    normalized_model = model_name.strip().lower()
    while normalized_model.startswith(("litellm/", "any-llm/")):
        normalized_model = normalized_model.split("/", 1)[1]
    extra_args: dict[str, Any] | None = None
    if normalized_model.startswith("anthropic/"):
        # LiteLLM translates this breakpoint to Anthropic cache_control.
        # The system message follows tool definitions in Anthropic's cache
        # prefix, so both the stable tool schema and system prompt are reused
        # across the long autonomous loop.
        extra_args = {
            "cache_control_injection_points": [
                {
                    "location": "message",
                    "role": "system",
                    "control": {"type": "ephemeral"},
                }
            ]
        }
    model_settings = ModelSettings(
        parallel_tool_calls=False,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        extra_args=extra_args,
    )
    if (
        reasoning_effort is not None
        and reasoning_effort != "none"
        and model_supports_reasoning(model_name)
    ):
        model_settings = model_settings.resolve(
            ModelSettings(reasoning=Reasoning(effort=reasoning_effort)),
        )
    return model_settings


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
    parent_history: list[Any],
) -> list[dict[str, Any]]:
    """Build the initial input for a child agent as a single user message.

    Collapsing the inherited-context block, the identity line, and the task into
    one ``{"role": "user"}`` message keeps providers that require strictly
    alternating roles (e.g. Perplexity, llama.cpp) from rejecting consecutive
    user messages.
    """
    parts: list[str] = []
    if parent_history:
        rendered = json.dumps(parent_history, ensure_ascii=False, default=str)
        parts.append(
            "== Inherited context from parent (background only) ==\n"
            f"{rendered}\n"
            "== End of inherited context ==\n"
            "Use the above as background only; do not continue the "
            "parent's work. Your task follows.",
        )
    parts.append(
        f"You are agent {name} ({child_id}); your parent is {parent_id}. "
        "Maintain your own identity. Call agent_finish when your task "
        "is complete.",
    )
    parts.append(task)
    return [{"role": "user", "content": "\n\n".join(parts)}]
