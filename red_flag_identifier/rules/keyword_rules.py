"""Built-in keyword and pattern-based rules for red flag detection."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RuleMatch:
    category: str
    severity: str  # low, medium, high, critical
    pattern: str
    description: str
    matched_text: str
    line_number: int
    context: str  # surrounding text for context
    source: str = "keyword"
    speaker: str = ""  # speaker/agent who said this


@dataclass
class Rule:
    category: str
    severity: str
    pattern: str
    description: str


COMPLIANCE_LEGAL_RULES = [
    Rule("compliance/legal", "critical", r"\bNDA\s+violation\b", "Potential NDA violation mentioned"),
    Rule("compliance/legal", "critical", r"\bbreach\s+of\s+contract\b", "Breach of contract reference"),
    Rule("compliance/legal", "critical", r"\binsider\s+trading\b", "Insider trading reference"),
    Rule("compliance/legal", "critical", r"\bmoney\s+laundering\b", "Money laundering reference"),
    Rule("compliance/legal", "high", r"\bconfidential\s+information\b", "Confidential information being discussed"),
    Rule("compliance/legal", "high", r"\btrade\s+secret\b", "Trade secret reference"),
    Rule("compliance/legal", "high", r"\bregulatory\s+violation\b", "Regulatory violation mentioned"),
    Rule("compliance/legal", "high", r"\bnon-?compliance\b", "Non-compliance mentioned"),
    Rule("compliance/legal", "high", r"\blawsuit\b", "Lawsuit reference"),
    Rule("compliance/legal", "high", r"\blitigation\b", "Litigation reference"),
    Rule("compliance/legal", "high", r"\bliability\b", "Legal liability mentioned"),
    Rule("compliance/legal", "medium", r"\boff\s+the\s+record\b", "Off the record statement"),
    Rule("compliance/legal", "medium", r"\bdon'?t\s+tell\s+anyone\b", "Secrecy request"),
    Rule("compliance/legal", "medium", r"\bkeep\s+(this|it)\s+quiet\b", "Request to keep information quiet"),
    Rule("compliance/legal", "medium", r"\bbetween\s+us\b", "Request for secrecy"),
    Rule("compliance/legal", "medium", r"\bunder\s+the\s+table\b", "Under the table dealing"),
    Rule("compliance/legal", "medium", r"\bconflict\s+of\s+interest\b", "Conflict of interest mentioned"),
    Rule("compliance/legal", "low", r"\bproprietary\b", "Proprietary information reference"),
    Rule("compliance/legal", "low", r"\bconfidential\b", "Confidentiality reference"),
    Rule("compliance/legal", "low", r"\bpending\s+(investigation|audit)\b", "Pending investigation or audit"),
]

BEHAVIORAL_HR_RULES = [
    Rule("behavioral/HR", "critical", r"\b(sexual\s+)?harassment\b", "Harassment mentioned"),
    Rule("behavioral/HR", "critical", r"\bdiscrimination\b", "Discrimination mentioned"),
    Rule("behavioral/HR", "critical", r"\bretaliation\b", "Retaliation mentioned"),
    Rule("behavioral/HR", "critical", r"\bhostile\s+work\s+environment\b", "Hostile work environment"),
    Rule("behavioral/HR", "high", r"\bthreatened?\b", "Threat mentioned"),
    Rule("behavioral/HR", "high", r"\bbullying\b", "Bullying mentioned"),
    Rule("behavioral/HR", "high", r"\bintimidation\b", "Intimidation mentioned"),
    Rule("behavioral/HR", "high", r"\binappropriate\s+(behavior|conduct|comment|touching)\b", "Inappropriate behavior"),
    Rule("behavioral/HR", "high", r"\bunwelcome\s+(advance|contact|comment)\b", "Unwelcome conduct"),
    Rule("behavioral/HR", "medium", r"\bfavoritism\b", "Favoritism mentioned"),
    Rule("behavioral/HR", "medium", r"\bunfair\s+treatment\b", "Unfair treatment mentioned"),
    Rule("behavioral/HR", "medium", r"\bhostile\b", "Hostile behavior"),
    Rule("behavioral/HR", "medium", r"\babusive\b", "Abusive behavior mentioned"),
    Rule("behavioral/HR", "medium", r"\byelling\b|\bscreaming\b", "Aggressive vocal behavior"),
    Rule("behavioral/HR", "medium", r"\bexclud(ed|ing)\b.*\b(meeting|team|project)\b", "Exclusion from work activities"),
    Rule("behavioral/HR", "low", r"\buncomfortable\b", "Discomfort expressed"),
    Rule("behavioral/HR", "low", r"\bunsafe\b", "Safety concern"),
    Rule("behavioral/HR", "low", r"\btoxic\b", "Toxic environment reference"),
]

SALES_FRAUD_RULES = [
    Rule("sales/fraud", "critical", r"\bguaranteed\s+returns?\b", "Guaranteed returns claim"),
    Rule("sales/fraud", "critical", r"\bno\s+risk\b", "No-risk claim"),
    Rule("sales/fraud", "critical", r"\bPonzi\b|\bpyramid\s+scheme\b", "Ponzi/pyramid scheme reference"),
    Rule("sales/fraud", "critical", r"\bembezzle?ment\b", "Embezzlement reference"),
    Rule("sales/fraud", "critical", r"\bforgery\b|\bforged\b", "Forgery reference"),
    Rule("sales/fraud", "high", r"\boff\s+the\s+books?\b", "Off the books transaction"),
    Rule("sales/fraud", "high", r"\bwire\s+transfer\b.*\b(immediate|urgent|now)\b", "Urgent wire transfer request"),
    Rule("sales/fraud", "high", r"\bfake\s+(invoice|receipt|document)\b", "Fake document reference"),
    Rule("sales/fraud", "high", r"\bcook(ing)?\s+the\s+books?\b", "Cooking the books reference"),
    Rule("sales/fraud", "high", r"\bfalsi(fy|fied|fication)\b", "Falsification reference"),
    Rule("sales/fraud", "high", r"\bmisrepresent(ation|ed|ing)?\b", "Misrepresentation"),
    Rule("sales/fraud", "medium", r"\bact\s+now\b|\blimited\s+time\b|\burgent\s+opportunity\b", "High-pressure sales tactic"),
    Rule("sales/fraud", "medium", r"\btoo\s+good\s+to\s+be\s+true\b", "Suspicious claim"),
    Rule("sales/fraud", "medium", r"\bdon'?t\s+need\s+to\s+(know|see|read)\b", "Discouraging due diligence"),
    Rule("sales/fraud", "medium", r"\bskip\s+(the\s+)?paperwork\b", "Avoiding documentation"),
    Rule("sales/fraud", "medium", r"\binflat(ed|ing)\s+(numbers?|figures?|results?)\b", "Inflated figures"),
    Rule("sales/fraud", "low", r"\bside\s+deal\b", "Side deal mentioned"),
    Rule("sales/fraud", "low", r"\bkickback\b", "Kickback reference"),
    Rule("sales/fraud", "low", r"\bunder-?report(ed|ing)?\b", "Under-reporting"),
]

ALL_BUILTIN_RULES = COMPLIANCE_LEGAL_RULES + BEHAVIORAL_HR_RULES + SALES_FRAUD_RULES


def scan_text(text: str, rules: list[Rule] | None = None) -> list[RuleMatch]:
    """Scan text against keyword rules and return matches."""
    if rules is None:
        rules = ALL_BUILTIN_RULES

    matches = []
    lines = text.split("\n")

    for rule in rules:
        for line_idx, line in enumerate(lines):
            for match in re.finditer(rule.pattern, line, re.IGNORECASE):
                # Get context: the matched line plus surrounding lines
                start = max(0, line_idx - 1)
                end = min(len(lines), line_idx + 2)
                context = "\n".join(lines[start:end])

                matches.append(RuleMatch(
                    category=rule.category,
                    severity=rule.severity,
                    pattern=rule.pattern,
                    description=rule.description,
                    matched_text=match.group(),
                    line_number=line_idx + 1,
                    context=context,
                    source="keyword",
                ))

    return matches
