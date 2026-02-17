"""Load user-defined custom rules from a JSON file."""

from __future__ import annotations

import json
from pathlib import Path

from .keyword_rules import Rule, RuleMatch, scan_text


def load_custom_rules(rules_path: str) -> list[Rule]:
    """Load custom rules from a JSON file.

    Expected format:
    [
        {
            "category": "custom/my-category",
            "severity": "high",
            "pattern": "regex pattern here",
            "description": "What this rule detects"
        }
    ]
    """
    path = Path(rules_path)
    if not path.exists():
        raise FileNotFoundError(f"Custom rules file not found: {rules_path}")

    with open(path) as f:
        data = json.load(f)

    rules = []
    for entry in data:
        rules.append(Rule(
            category=entry.get("category", "custom"),
            severity=entry.get("severity", "medium"),
            pattern=entry["pattern"],
            description=entry.get("description", "Custom rule match"),
        ))

    return rules


def scan_with_custom_rules(text: str, rules_path: str) -> list[RuleMatch]:
    """Scan text using custom rules from a JSON file."""
    rules = load_custom_rules(rules_path)
    matches = scan_text(text, rules)
    for match in matches:
        match.source = "custom"
    return matches
