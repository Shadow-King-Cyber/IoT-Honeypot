"""Tests para telnet_honeypot."""

from iot_honeypot.honeypot.telnet_honeypot import (
    simulate_telnet_login, get_default_credentials, create_session, simulate_command
)


def test_login_admin_admin():
    assert simulate_telnet_login("admin", "admin") is True


def test_login_root_root():
    assert simulate_telnet_login("root", "root") is True


def test_login_fallido():
    assert simulate_telnet_login("admin", "wrongpass") is False


def test_default_credentials():
    creds = get_default_credentials()
    assert len(creds) > 0
    assert any(c["username"] == "admin" for c in creds)


def test_session_creation():
    session = create_session("192.168.1.1")
    assert session.source_ip == "192.168.1.1"
    assert session.authenticated is False


def test_command_no_auth():
    session = create_session("192.168.1.1")
    resp = simulate_command(session, "whoami")
    assert resp == "Login required"


def test_command_whoami():
    session = create_session("192.168.1.1")
    session.authenticated = True
    resp = simulate_command(session, "whoami")
    assert resp == "root"
