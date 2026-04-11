import os
import logging
from flask import Flask, render_template_string, request, redirect, url_for, send_file
from pathlib import Path
from werkzeug.utils import secure_filename
import json

import config
from core.engine import Engine
from core.models import Report
from core.utils import load_json
from reports.generator import ReportGenerator
from intelligence.correlator import Correlator
from intelligence.enricher import Enricher
from intelligence.compliance import ComplianceMapper

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "autosecaudit_secret_key_change_in_production"

HTML_FORM = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoSecAudit 2.0</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { max-width: 600px; width: 100%; padding: 20px; }
        h1 { color: #00d9ff; text-align: center; margin-bottom: 10px; }
        .subtitle { color: #888; text-align: center; margin-bottom: 30px; }
        .card { background: #16213e; padding: 30px; border-radius: 10px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #aaa; }
        input[type="text"], input[type="file"] { width: 100%; padding: 12px; border: 1px solid #0f3460; border-radius: 5px; background: #0d0d1a; color: #eee; font-size: 16px; }
        input[type="file"] { cursor: pointer; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #00d9ff, #0099cc); border: none; border-radius: 5px; color: #1a1a2e; font-size: 16px; font-weight: bold; cursor: pointer; transition: transform 0.2s; }
        button:hover { transform: scale(1.02); }
        .note { color: #666; font-size: 0.85em; margin-top: 10px; }
        .recent { margin-top: 30px; }
        .recent h3 { color: #00d9ff; margin-bottom: 15px; }
        .report-list { list-style: none; }
        .report-list li { background: #0f3460; margin: 8px 0; padding: 12px; border-radius: 5px; }
        .report-list a { color: #00d9ff; text-decoration: none; }
        .report-list a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AutoSecAudit 2.0</h1>
        <p class="subtitle">Intelligent Security Auditing Framework</p>
        
        <div class="card">
            <form method="POST" action="/scan" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="target">Target URL or IP Address</label>
                    <input type="text" id="target" name="target" placeholder="e.g., example.com or 192.168.1.1" required>
                </div>
                
                <div class="form-group">
                    <label for="previous_report">Upload Previous Report (optional)</label>
                    <input type="file" id="previous_report" name="previous_report" accept=".json">
                </div>
                
                <button type="submit">🚀 Start Security Scan</button>
                <p class="note">Note: Running in MOCK mode for demo. Set AUTOSEC_MOCK_MODE=false for real scans.</p>
            </form>
        </div>
        
        <div class="recent">
            <h3>Recent Reports</h3>
            <ul class="report-list">
            {% for report in recent_reports %}
                <li><a href="/report/{{ report }}">{{ report }}</a></li>
            {% else %}
                <li>No reports yet</li>
            {% endfor %}
            </ul>
        </div>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    reports_dir = Path(config.REPORTS_DIR)
    if reports_dir.exists():
        reports = [f.stem.replace("scan_", "") for f in reports_dir.glob("scan_*.json")]
        reports.sort(reverse=True)
        reports = reports[:5]
    else:
        reports = []
    return render_template_string(HTML_FORM, recent_reports=reports)


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return "Target is required", 400
    
    previous_file = request.files.get("previous_report")
    previous_path = None
    if previous_file and previous_file.filename:
        filename = secure_filename(previous_file.filename)
        previous_path = f"{config.DATA_DIR}/temp_{filename}"
        previous_file.save(previous_path)
    
    engine = Engine()
    engine.load_plugins()
    
    if not engine.set_target(target):
        return "Invalid target", 400
    
    if previous_path:
        engine.set_previous_report(previous_path)
    
    engine.run_plugins()
    report = engine.generate_report()
    
    if previous_path and engine.previous_report:
        from intelligence.delta import DeltaAnalyzer
        previous_data = load_json(previous_path)
        if previous_data:
            from core.models import Finding
            prev_findings = [Finding(**f) for f in previous_data.get("all_findings", [])]
            prev_report = Report(
                target=previous_data.get("target", ""),
                timestamp=previous_data.get("timestamp", ""),
                all_findings=prev_findings
            )
            delta = DeltaAnalyzer().compare(report, prev_report)
            report.delta = delta
    
    correlator = Correlator()
    report.all_findings = correlator.link_related(report.all_findings)
    
    enricher = Enricher()
    report.all_findings = enricher.enrich(report.all_findings)
    
    mapper = ComplianceMapper()
    report.all_findings = mapper.map_findings(report.all_findings)
    
    report.summary = engine._generate_summary(report.all_findings)
    
    json_path = engine.save_report(report)
    
    generator = ReportGenerator()
    html_path = generator.generate_report(report)
    
    report_name = Path(json_path).stem.replace("scan_", "")
    
    return redirect(url_for("view_report", report_id=report_name))


@app.route("/report/<report_id>")
def view_report(report_id):
    json_path = f"{config.REPORTS_DIR}/scan_{report_id}.json"
    report_data = load_json(json_path)
    
    if not report_data:
        return "Report not found", 404
    
    template_path = Path(__file__).parent.parent / "reports" / "templates" / "report.html"
    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()
    
    from jinja2 import Template
    template = Template(template_content)
    html = template.render(report=report_data)
    
    return html


@app.route("/download/<report_id>")
def download_report(report_id):
    json_path = f"{config.REPORTS_DIR}/scan_{report_id}.json"
    return send_file(json_path, as_attachment=True, download_name=f"report_{report_id}.json")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
