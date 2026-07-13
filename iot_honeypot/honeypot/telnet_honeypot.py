"""Honeypot Telnet — emula servidor Telnet IoT con credenciales por defecto."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_CREDENTIALS: list[dict[str, str]] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "toor"},
    {"username": "admin", "password": "1234"},
    {"username": "root", "password": "admin"},
    {"username": "user", "password": "user"},
    {"username": "ubnt", "password": "ubnt"},
    {"username": "support", "password": "support"},
    {"username": "guest", "password": "guest"},
]


@dataclass
class TelnetSession:
    """Sesión Telnet simulada."""
    source_ip: str
    username: str
    password: str
    authenticated: bool
    commands_executed: list[str]


def simulate_telnet_login(username: str, password: str) -> bool:
    """Simula un login Telnet — verifica contra credenciales por defecto."""
    return any(
        c["username"] == username and c["password"] == password
        for c in DEFAULT_CREDENTIALS
    )


def get_default_credentials() -> list[dict[str, str]]:
    """Devuelve las credenciales por defecto conocidas."""
    return DEFAULT_CREDENTIALS.copy()


def create_session(source_ip: str) -> TelnetSession:
    """Crea una sesión Telnet simulada."""
    return TelnetSession(
        source_ip=source_ip,
        username="",
        password="",
        authenticated=False,
        commands_executed=[],
    )


def simulate_command(session: TelnetSession, command: str) -> str:
    """Simula la ejecución de un comando Telnet."""
    session.commands_executed.append(command)
    if not session.authenticated:
        return "Login required"

    responses = {
        "help": "Available commands: ls, id, whoami, uname, cat",
        "ls": "bin  etc  lib  proc  sbin  usr  var",
        "id": "uid=0(root) gid=0(root)",
        "whoami": "root",
        "uname": "Linux iot-device 4.14.0 #1 SMP Mon Jan 1 00:00:00 UTC 2024 armv7l",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/sh",
    }
    return responses.get(command, f"sh: {command}: not found")
