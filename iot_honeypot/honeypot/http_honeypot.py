"""Honeypot HTTP — emula cámara web o router IoT."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HTTPResponse:
    """Respuesta HTTP simulada."""
    status_code: int
    headers: dict[str, str]
    body: str


# Páginas de login falsas para dispositivos IoT simulados
LOGIN_PAGES = {
    "ip_camera": {
        "title": "IP Camera Login",
        "brand": "Hikvision DS-2CD2143G2-I",
        "firmware": "V5.6.100 build 210702",
    },
    "router": {
        "title": "Router Admin Panel",
        "brand": "TP-Link Archer C7",
        "firmware": "3.17.0 Build 220114",
    },
    "iot_gateway": {
        "title": "Smart Home Gateway",
        "brand": "Xiaomi Mi Gateway 3",
        "firmware": "1.4.6_163.0143",
    },
}


def simulate_http_request(path: str, device_type: str = "ip_camera") -> HTTPResponse:
    """Simula una petición HTTP al honeypot."""
    device = LOGIN_PAGES.get(device_type, LOGIN_PAGES["ip_camera"])

    if path == "/":
        return HTTPResponse(
            status_code=200,
            headers={"Server": "Boa/0.94.14rc21", "Content-Type": "text/html"},
            body=f"<html><head><title>{device['title']}</title></head>"
                 f"<body><h1>{device['brand']}</h1>"
                 f"<p>Firmware: {device['firmware']}</p>"
                 f"<form action='/login' method='POST'>"
                 f"<input name='username' placeholder='Username'>"
                 f"<input name='password' type='password' placeholder='Password'>"
                 f"<button type='submit'>Login</button></form></body></html>",
        )
    elif path == "/login":
        return HTTPResponse(
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
            body="401 Unauthorized",
        )
    elif path == "/env":
        return HTTPResponse(
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body="APPVER=V5.6.100\nDEVTYPE=IPCAM\nSN=123456789",
        )
    else:
        return HTTPResponse(status_code=404, headers={}, body="404 Not Found")


def get_supported_devices() -> list[str]:
    """Devuelve los tipos de dispositivos soportados."""
    return list(LOGIN_PAGES.keys())
