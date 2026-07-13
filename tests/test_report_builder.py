"""Tests para report_builder."""

from iot_honeypot.reporting.report_builder import HoneypotReport, HoneypotFinding


def test_build_summary():
    report = HoneypotReport(device_type="ip_camera")
    report.findings.append(HoneypotFinding(category="a", detail="d", severity="Critico"))
    report.findings.append(HoneypotFinding(category="b", detail="d", severity="Alto"))
    report.build_summary()
    assert report.summary["Critico"] == 1
    assert report.overall_severity == "Critico"


def test_summary_vacio():
    report = HoneypotReport(device_type="router")
    report.build_summary()
    assert report.overall_severity == "Info"
