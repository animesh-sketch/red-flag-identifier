"""Main analysis orchestrator - combines keyword, custom, and AI analysis."""

from __future__ import annotations

from .ai_analyzer import analyze_with_ai
from .rules.custom_rules import scan_with_custom_rules
from .rules.keyword_rules import RuleMatch, scan_text

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def analyze(
    text: str,
    mode: str = "hybrid",
    custom_rules_path: str | None = None,
    api_key: str | None = None,
    min_severity: str = "low",
) -> list[RuleMatch]:
    """Run full analysis pipeline on the given text.

    Args:
        text: The transcript text to analyze.
        mode: "hybrid" (default), "rules-only", or "ai-only".
        custom_rules_path: Optional path to custom rules JSON file.
        api_key: Optional Anthropic API key for AI analysis.
        min_severity: Minimum severity to include in results.

    Returns:
        List of RuleMatch findings, sorted by severity.
    """
    all_matches: list[RuleMatch] = []

    # Run keyword rules
    if mode in ("hybrid", "rules-only"):
        all_matches.extend(scan_text(text))

    # Run custom rules
    if custom_rules_path and mode in ("hybrid", "rules-only"):
        all_matches.extend(scan_with_custom_rules(text, custom_rules_path))

    # Run AI analysis
    if mode in ("hybrid", "ai-only"):
        ai_matches = analyze_with_ai(text, api_key)
        all_matches.extend(ai_matches)

    # Filter by minimum severity
    min_level = SEVERITY_ORDER.get(min_severity, 3)
    all_matches = [m for m in all_matches if SEVERITY_ORDER.get(m.severity, 3) <= min_level]

    # Deduplicate: if AI and keyword found the same thing on the same line, prefer AI
    all_matches = _deduplicate(all_matches)

    # Sort by severity (critical first)
    all_matches.sort(key=lambda m: SEVERITY_ORDER.get(m.severity, 3))

    return all_matches


def _deduplicate(matches: list[RuleMatch]) -> list[RuleMatch]:
    """Remove duplicate findings. When keyword and AI flag the same line, prefer AI."""
    seen: dict[tuple[int, str], RuleMatch] = {}

    for match in matches:
        key = (match.line_number, match.category)
        existing = seen.get(key)
        if existing is None:
            seen[key] = match
        elif match.source == "ai" and existing.source != "ai":
            # Prefer AI match as it has more context
            seen[key] = match
        elif match.source == existing.source:
            # Same source, different pattern on same line - keep both by making key unique
            unique_key = (match.line_number, match.category, match.matched_text)
            seen[unique_key] = match

    return list(seen.values())
