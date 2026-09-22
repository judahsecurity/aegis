"""SDK run hooks used by Aegis orchestration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from aegis.detection.evidence import assess_http_evidence
from aegis.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse


logger = logging.getLogger(__name__)


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class BudgetFinalizationRequiredError(BudgetExceededError):
    """Raised when findings exist and the reserved finalization budget is reached."""


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response."""

    def __init__(self, *, model: str, max_budget_usd: float | None = None) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        self._model = model
        self._max_budget_usd = max_budget_usd

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        if report_state is None:
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)

        if self._max_budget_usd is not None:
            cost = report_state.get_total_llm_cost()
            reports = getattr(report_state, "vulnerability_reports", None)
            has_verified_findings = isinstance(reports, list) and any(
                (
                    isinstance(report.get("evidence_assessment"), dict)
                    and report["evidence_assessment"].get("level") == "verified"
                )
                or assess_http_evidence(
                    report.get("http_requests")
                    if isinstance(report.get("http_requests"), list)
                    else None
                ).level
                == "verified"
                for report in reports
                if isinstance(report, dict)
            )
            reserve_threshold = self._max_budget_usd * 0.9
            if has_verified_findings and cost >= reserve_threshold:
                raise BudgetFinalizationRequiredError(
                    f"Finding-preservation threshold of ${reserve_threshold:.2f} reached "
                    f"(spent ${cost:.4f}; hard limit ${self._max_budget_usd:.2f})"
                )
            if cost >= self._max_budget_usd:
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
