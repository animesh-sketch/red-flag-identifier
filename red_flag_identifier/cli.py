"""CLI entry point for the Red Flag Identifier."""

import argparse
import sys

from rich.console import Console

from .analyzer import analyze
from .reporter import report_json, report_text


def main():
    parser = argparse.ArgumentParser(
        prog="red-flag-identifier",
        description="Analyze transcripts and text for red flags across compliance, HR, fraud, and custom categories.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        default=None,
        help="Path to transcript file, or '-' to read from stdin",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch web interface instead of CLI",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for web server (default: 5000)",
    )
    parser.add_argument(
        "--rules",
        help="Path to custom rules JSON file",
        default=None,
    )
    parser.add_argument(
        "--mode",
        choices=["hybrid", "rules-only", "ai-only"],
        default="hybrid",
        help="Analysis mode (default: hybrid)",
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--api-key",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)",
        default=None,
    )

    args = parser.parse_args()

    # Web mode
    if args.web:
        from .web import run_server
        print(f"Starting Red Flag Identifier web server...")
        print(f"Open http://127.0.0.1:{args.port} in your browser")
        run_server(port=args.port, debug=True)
        return

    if not args.file:
        parser.error("file is required (or use --web for web interface)")

    # Read input
    if args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            with open(args.file) as f:
                text = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not text.strip():
        print("Error: Input is empty.", file=sys.stderr)
        sys.exit(1)

    console = Console(stderr=True)

    # Show mode info
    if args.output_format == "text":
        mode_label = args.mode
        if args.mode in ("hybrid", "ai-only"):
            import os
            has_key = bool(args.api_key or os.environ.get("ANTHROPIC_API_KEY"))
            if not has_key:
                console.print("[yellow]Warning: No API key found. AI analysis will be skipped.[/yellow]")
                console.print("[dim]Set ANTHROPIC_API_KEY or use --api-key to enable AI analysis.[/dim]")
                if args.mode == "ai-only":
                    console.print("[red]Error: ai-only mode requires an API key.[/red]")
                    sys.exit(1)
                mode_label = "rules-only (fallback)"
        console.print(f"[dim]Mode: {mode_label} | Min severity: {args.severity}[/dim]")
        console.print("[dim]Analyzing...[/dim]")

    # Run analysis
    matches = analyze(
        text=text,
        mode=args.mode,
        custom_rules_path=args.rules,
        api_key=args.api_key,
        min_severity=args.severity,
    )

    # Output results
    if args.output_format == "json":
        print(report_json(matches))
    else:
        report_text(matches, Console())


if __name__ == "__main__":
    main()
