"""Format and display red flag analysis results."""

from __future__ import annotations

import json
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .rules.keyword_rules import RuleMatch

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

SEVERITY_ICONS = {
    "critical": "[!!!]",
    "high": "[!!]",
    "medium": "[!]",
    "low": "[i]",
}


def report_text(matches: list[RuleMatch], console: Console | None = None) -> None:
    """Display results as rich-formatted terminal output."""
    if console is None:
        console = Console()

    if not matches:
        console.print(Panel("[bold green]No red flags found.[/bold green]", title="Results"))
        return

    # Header
    console.print()
    console.print(Panel(
        f"[bold]Found {len(matches)} red flag(s)[/bold]",
        title="Red Flag Analysis Results",
        border_style="red",
    ))
    console.print()

    # Results table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=18)
    table.add_column("Line", width=6)
    table.add_column("Description", ratio=2)
    table.add_column("Flagged Text", ratio=2)
    table.add_column("Source", width=8)

    for i, match in enumerate(matches, 1):
        severity_style = SEVERITY_COLORS.get(match.severity, "white")
        icon = SEVERITY_ICONS.get(match.severity, "")

        severity_text = Text(f"{icon} {match.severity.upper()}")
        severity_text.stylize(severity_style)

        flagged = match.matched_text[:80]
        if len(match.matched_text) > 80:
            flagged += "..."

        table.add_row(
            str(i),
            severity_text,
            match.category,
            str(match.line_number) if match.line_number else "-",
            match.description,
            flagged,
            match.source,
        )

    console.print(table)

    # Summary
    console.print()
    severity_counts = Counter(m.severity for m in matches)
    category_counts = Counter(m.category for m in matches)

    summary_table = Table(title="Summary", show_header=True, header_style="bold")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Count")

    for sev in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            style = SEVERITY_COLORS.get(sev, "white")
            summary_table.add_row(f"{sev.upper()}", f"[{style}]{count}[/{style}]")

    summary_table.add_section()
    for cat, count in sorted(category_counts.items()):
        summary_table.add_row(cat, str(count))

    console.print(summary_table)
    console.print()


def report_json(matches: list[RuleMatch]) -> str:
    """Return results as a JSON string."""
    results = {
        "total": len(matches),
        "findings": [
            {
                "category": m.category,
                "severity": m.severity,
                "description": m.description,
                "matched_text": m.matched_text,
                "line_number": m.line_number,
                "context": m.context,
                "source": m.source,
            }
            for m in matches
        ],
        "summary": {
            "by_severity": dict(Counter(m.severity for m in matches)),
            "by_category": dict(Counter(m.category for m in matches)),
        },
    }
    return json.dumps(results, indent=2)
