"""Vercel serverless entry point for the Red Flag Identifier."""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs

# Add parent directory to path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from red_flag_identifier.analyzer import analyze

# Read the HTML template at module load time
TEMPLATE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "red_flag_identifier", "templates", "index.html"
)
with open(TEMPLATE_PATH) as f:
    INDEX_HTML = f.read()


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(INDEX_HTML.encode("utf-8"))

    def do_POST(self):
        if self.path != "/analyze":
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Invalid JSON"})
            return

        text = (data.get("text") or "").strip()
        mode = data.get("mode", "rules-only")
        severity = data.get("severity", "low")
        api_key = (data.get("api_key") or "").strip() or os.environ.get("ANTHROPIC_API_KEY")
        call_date = data.get("call_date", "")

        if not text:
            self.send_json(400, {"error": "No text provided. Paste text or upload a file."})
            return

        if mode in ("hybrid", "ai-only") and not api_key:
            self.send_json(400, {"error": "API key required for AI analysis. Use rules-only mode or provide an API key."})
            return

        try:
            matches = analyze(
                text=text,
                mode=mode,
                api_key=api_key,
                min_severity=severity,
            )
        except Exception as e:
            self.send_json(500, {"error": str(e)})
            return

        results = [
            {
                "category": m.category,
                "severity": m.severity,
                "description": m.description,
                "matched_text": m.matched_text,
                "line_number": m.line_number,
                "context": m.context,
                "source": m.source,
                "speaker": m.speaker,
            }
            for m in matches
        ]

        # Build agent summary
        agent_summary = {}
        for m in matches:
            if m.speaker:
                if m.speaker not in agent_summary:
                    agent_summary[m.speaker] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "categories": {}}
                agent_summary[m.speaker]["total"] += 1
                agent_summary[m.speaker][m.severity] = agent_summary[m.speaker].get(m.severity, 0) + 1
                cat = m.category
                agent_summary[m.speaker]["categories"][cat] = agent_summary[m.speaker]["categories"].get(cat, 0) + 1

        sorted_agents = sorted(agent_summary.items(), key=lambda x: x[1]["total"], reverse=True)
        agent_summary_sorted = [{"name": name, **data} for name, data in sorted_agents]

        self.send_json(200, {
            "total": len(results),
            "findings": results,
            "call_date": call_date,
            "agent_summary": agent_summary_sorted,
        })

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
