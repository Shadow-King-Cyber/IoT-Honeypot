"""Tests para attack_classifier."""

from iot_honeypot.detection.attack_classifier import classify_attack, get_attack_types


def test_classify_brute_force():
    cmds = ["login", "login", "login", "password", "auth"]
    result = classify_attack(cmds, "192.168.1.1")
    assert len(result) > 0
    assert any(r.attack_type == "brute_force" for r in result)


def test_classify_command_injection():
    cmds = ["; cat /etc/passwd", "ls"]
    result = classify_attack(cmds, "10.0.0.1")
    assert any(r.attack_type == "command_injection" for r in result)


def test_get_attack_types():
    types = get_attack_types()
    assert len(types) > 0
    assert "brute_force" in types
