"""Exportador JSON de reportes IoT."""

from __future__ import annotations

import json
from pathlib import Path

from .report_builder import HoneypotReport


def export_json(report: HoneypotReport, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "device_type": report.device_type,
        "overall_severity": report.overall_severity,
        "summary": report.summary,
        "findings": [
            {"category": f.category, "detail": f.detail, "severity": f.severity, "source_ip": f.source_ip, "evidence": f.evidence}
            for f in report.findings
        ],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return output_path
