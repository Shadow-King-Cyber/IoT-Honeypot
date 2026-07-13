"""Exportador HTML de reportes IoT con Chart.js."""

from __future__ import annotations

from pathlib import Path
from jinja2 import Environment

from .report_builder import HoneypotReport


def _get_template() -> str:
    return """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"><title>IoT-Honeypot Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#ff6b6b}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #30363d;padding:8px;text-align:left}
th{background:#161b22}canvas{max-width:400px;margin:20px auto}</style>
</head>
<body>
<h1>IoT-Honeypot Report</h1>
<p><strong>Device:</strong> {{ report.device_type }} | <strong>Risk:</strong> {{ report.overall_severity }}</p>
<div style="display:flex;gap:10px">
{% for l,c in report.summary.items() %}
<div style="padding:10px;border-radius:8px;text-align:center"><b>{{ c }}</b><br>{{ l }}</div>
{% endfor %}</div>
<canvas id="chart"></canvas>
<table><tr><th>Category</th><th>Detail</th><th>Severity</th><th>Source IP</th></tr>
{% for f in report.findings %}
<tr><td>{{ f.category }}</td><td>{{ f.detail }}</td><td>{{ f.severity }}</td><td>{{ f.source_ip }}</td></tr>
{% endfor %}</table>
<script>new Chart(document.getElementById('chart'),{type:'doughnut',data:{labels:['Critico','Alto','Medio','Bajo','Info'],datasets:[{data:[{{ report.summary.get('Critico',0) }},{{ report.summary.get('Alto',0) }},{{ report.summary.get('Medio',0) }},{{ report.summary.get('Bajo',0) }},{{ report.summary.get('Info',0) }}],backgroundColor:['#8b0000','#cc5500','#ccaa00','#228b22','#444']}]}});</script>
</body></html>"""


def export_html(report: HoneypotReport, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment()
    template = env.from_string(_get_template())
    html = template.render(report=report)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path
