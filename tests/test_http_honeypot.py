"""Tests para http_honeypot."""

from iot_honeypot.honeypot.http_honeypot import simulate_http_request, get_supported_devices


def test_http_root():
    resp = simulate_http_request("/")
    assert resp.status_code == 200
    assert "login" in resp.body.lower()


def test_http_404():
    resp = simulate_http_request("/noexiste")
    assert resp.status_code == 404


def test_http_login():
    resp = simulate_http_request("/login")
    assert resp.status_code == 401


def test_http_env():
    resp = simulate_http_request("/env")
    assert resp.status_code == 200
    assert "APPVER" in resp.body


def test_supported_devices():
    devices = get_supported_devices()
    assert "ip_camera" in devices
    assert "router" in devices
