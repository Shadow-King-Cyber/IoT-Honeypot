"""Tests para threat_scoring."""

from iot_honeypot.scoring.threat_scoring import get_threat_level, calculate_threat_score


def test_threat_levels():
    assert get_threat_level("brute_force") == "Alto"
    assert get_threat_level("command_injection") == "Critico"
    assert get_threat_level("scanning") == "Medio"
    assert get_threat_level("unknown") == "Info"


def test_calculate_threat_score():
    attacks = ["brute_force", "scanning", "reconnaissance"]
    result = calculate_threat_score(attacks)
    assert result["summary"]["Alto"] == 1
    assert result["summary"]["Medio"] == 1
    assert result["summary"]["Bajo"] == 1
    assert result["overall"] == "Alto"


def test_score_vacio():
    result = calculate_threat_score([])
    assert result["overall"] == "Info"
