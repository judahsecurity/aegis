"""Verification agent for reviewing testing thoroughness."""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool

from aegis.tools.enforcement.minimums import MANDATORY_CATEGORIES
from aegis.tools.enforcement.tracker import get_tracker


@function_tool(timeout=30, strict_mode=False)
async def verify_category(
    ctx: RunContextWrapper,
    category: str,
) -> str:
    """Check if a category meets minimum requirements.

    Use this BEFORE calling track_category_tested to verify your testing
    was thorough enough. This is OPTIONAL — you can call track_category_tested
    directly if you're confident you met the minimums.

    Args:
        category: One of the 8 mandatory category IDs.
    """
    if category not in MANDATORY_CATEGORIES:
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"Invalid category: {category}. Valid: "
                    f"{', '.join(sorted(MANDATORY_CATEGORIES))}"
                ),
            }
        )

    tracker = get_tracker(ctx)
    passed, missing_reasons = tracker.check_minimums(category)
    stats = tracker.get_category_stats(category)

    return json.dumps(
        {
            "success": True,
            "category": category,
            "minimums_met": passed,
            "missing_reasons": missing_reasons,
            "unique_tests": stats["unique_tests"],
            "unique_endpoints": stats["unique_endpoints"],
            "tools_used": sorted(stats["tools_used"]),
        },
        ensure_ascii=False,
        default=str,
    )
