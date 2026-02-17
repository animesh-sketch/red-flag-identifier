"""Flask web interface for the Red Flag Identifier."""

import os

from flask import Flask, render_template, request, jsonify

from .analyzer import analyze

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_text():
    # Accept both JSON and form data
    if request.is_json:
        data = request.get_json()
        text = (data.get("text") or "").strip()
        mode = data.get("mode", "rules-only")
        severity = data.get("severity", "low")
        api_key = (data.get("api_key") or "").strip() or os.environ.get("ANTHROPIC_API_KEY")
    else:
        text = request.form.get("text", "").strip()
        file = request.files.get("file")
        mode = request.form.get("mode", "rules-only")
        severity = request.form.get("severity", "low")
        api_key = request.form.get("api_key", "").strip() or os.environ.get("ANTHROPIC_API_KEY")
        if file and file.filename:
            text = file.read().decode("utf-8", errors="replace")

    if not text:
        return jsonify({"error": "No text provided. Paste text or upload a file."}), 400

    if mode in ("hybrid", "ai-only") and not api_key:
        return jsonify({"error": "API key required for AI analysis. Use rules-only mode or provide an API key."}), 400

    try:
        matches = analyze(
            text=text,
            mode=mode,
            api_key=api_key,
            min_severity=severity,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    results = [
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
    ]

    return jsonify({"total": len(results), "findings": results})


def run_server(host="127.0.0.1", port=5000, debug=False):
    app.run(host=host, port=port, debug=debug)
