"""Constructor de reportes IoT."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HoneypotFinding:
    category: str
    detail: str
    severity: str
    source_ip: str = ""
    evidence: str = ""


@dataclass
class HoneypotReport:
    device_type: str
    findings: list[HoneypotFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    overall_severity: str = "Info"

    def build_summary(self) -> None:
        summary: dict[str, int] = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0, "Info": 0}
        for f in self.findings:
            if f.severity in summary:
                summary[f.severity] += 1
        self.summary = summary
        values = {"Critico": 4, "Alto": 3, "Medio": 2, "Bajo": 1, "Info": 0}
        max_val = max((values.get(f.severity, 0) for f in self.findings), default=0)
        self.overall_severity = {v: k for k, v in values.items()}.get(max_val, "Info")
