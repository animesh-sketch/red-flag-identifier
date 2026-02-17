"""AI-powered red flag analysis using Claude API."""

from __future__ import annotations

import json
import os
import time

from .rules.keyword_rules import RuleMatch

SYSTEM_PROMPT = """You are a red flag analyzer. Your job is to carefully read transcripts and identify potential red flags across these categories:

1. **Compliance/Legal**: NDA violations, regulatory breaches, legal risks, confidentiality violations, conflicts of interest
2. **Behavioral/HR**: Harassment, discrimination, bullying, hostile behavior, retaliation, inappropriate conduct
3. **Sales/Fraud**: Misleading claims, fraudulent statements, pressure tactics, falsification, embezzlement
4. **General**: Any other concerning patterns that don't fit the above categories

For each red flag found, assess its severity:
- **critical**: Immediate action required, potential legal/safety risk
- **high**: Serious concern requiring prompt attention
- **medium**: Notable concern worth investigating
- **low**: Minor concern, worth monitoring

Respond ONLY with a valid JSON array. Each element must have these fields:
- "category": one of "compliance/legal", "behavioral/HR", "sales/fraud", "general"
- "severity": one of "critical", "high", "medium", "low"
- "quote": the exact text from the transcript that triggered the flag (keep it short, 1-2 sentences max)
- "explanation": brief explanation of why this is a red flag
- "line_hint": approximate line number where this appears (best guess)

If no red flags are found, return an empty array: []

Be thorough but avoid false positives. Focus on genuinely concerning statements, not benign mentions of keywords."""

# Keep under 25K tokens per chunk to respect low rate limits (30K tokens/min)
# ~4 chars/token, minus overhead for line prefixes and system prompt
MAX_CHARS_PER_CHUNK = 80_000

# Seconds to wait between API calls to respect rate limits
DELAY_BETWEEN_CHUNKS = 65


def _split_into_chunks(text: str) -> list[tuple[str, int]]:
    """Split text into chunks that fit within the token limit.

    Returns list of (chunk_text, start_line_number) tuples.
    """
    lines = text.split("\n")
    chunks = []
    current_chunk_lines = []
    current_chars = 0
    chunk_start_line = 1

    for i, line in enumerate(lines):
        line_chars = len(line) + 1  # +1 for newline
        if current_chars + line_chars > MAX_CHARS_PER_CHUNK and current_chunk_lines:
            chunks.append(("\n".join(current_chunk_lines), chunk_start_line))
            current_chunk_lines = []
            current_chars = 0
            chunk_start_line = i + 1

        current_chunk_lines.append(line)
        current_chars += line_chars

    if current_chunk_lines:
        chunks.append(("\n".join(current_chunk_lines), chunk_start_line))

    return chunks


def _analyze_chunk(client, chunk_text: str, start_line: int, chunk_num: int, total_chunks: int) -> list[dict]:
    """Analyze a single chunk of text with Claude API."""
    numbered_lines = []
    for i, line in enumerate(chunk_text.split("\n"), start_line):
        numbered_lines.append(f"[Line {i}] {line}")
    numbered_text = "\n".join(numbered_lines)

    chunk_note = ""
    if total_chunks > 1:
        chunk_note = f"\n\nNote: This is chunk {chunk_num}/{total_chunks} of a larger transcript. Line numbers are from the original document."

    max_retries = 3
    for attempt in range(max_retries):
        try:
            message = client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": f"Analyze this transcript for red flags:{chunk_note}\n\n{numbered_text}"}
                ],
            )
            break
        except Exception as e:
            error_msg = str(e)
            if "authentication_error" in error_msg or "401" in error_msg:
                raise RuntimeError("Invalid API key. Please check your Anthropic API key and try again.")
            if "credit balance" in error_msg or "billing" in error_msg.lower():
                raise RuntimeError("Insufficient credits. Please add credits at console.anthropic.com/settings/billing")
            if "rate_limit" in error_msg or "429" in error_msg:
                if attempt < max_retries - 1:
                    time.sleep(DELAY_BETWEEN_CHUNKS)
                    continue
                raise RuntimeError(f"Rate limit exceeded after {max_retries} retries. Try again in a minute or use a shorter transcript.")
            raise RuntimeError(f"AI analysis failed: {error_msg}")

    response_text = message.content[0].text

    try:
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.rsplit("```", 1)[0]
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return []


def analyze_with_ai(text: str, api_key: str | None = None) -> list[RuleMatch]:
    """Analyze text using Claude API for intelligent red flag detection."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return []

    try:
        from anthropic import Anthropic
    except ImportError:
        print("Warning: anthropic package not installed. Skipping AI analysis.")
        print("Install with: pip install anthropic")
        return []

    client = Anthropic(api_key=key)
    chunks = _split_into_chunks(text)
    all_findings = []

    for i, (chunk_text, start_line) in enumerate(chunks, 1):
        if i > 1:
            # Wait between chunks to respect rate limits
            time.sleep(DELAY_BETWEEN_CHUNKS)
        findings = _analyze_chunk(client, chunk_text, start_line, i, len(chunks))
        all_findings.extend(findings)

    matches = []
    for finding in all_findings:
        matches.append(RuleMatch(
            category=finding.get("category", "general"),
            severity=finding.get("severity", "medium"),
            pattern="",
            description=finding.get("explanation", "AI-detected red flag"),
            matched_text=finding.get("quote", ""),
            line_number=finding.get("line_hint", 0),
            context=finding.get("quote", ""),
            source="ai",
        ))

    return matches
