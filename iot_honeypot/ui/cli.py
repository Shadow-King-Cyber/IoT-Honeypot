"""CLI para IoT-Honeypot usando Click."""

from __future__ import annotations

import click

from ..honeypot.telnet_honeypot import simulate_telnet_login, get_default_credentials, create_session, simulate_command
from ..honeypot.http_honeypot import simulate_http_request
from ..honeypot.mqtt_honeypot import simulate_mqtt_message, simulate_broker_status
from ..detection.attack_classifier import classify_attack, get_attack_types
from ..scoring.threat_scoring import get_threat_level, calculate_threat_score
from ..reporting.report_builder import HoneypotReport, HoneypotFinding
from ..reporting.json_exporter import export_json


@click.group()
def cli() -> None:
    """IoT-Honeypot — Honeypot IoT."""
    pass


@cli.command()
@click.option("--username", required=True)
@click.option("--password", required=True)
@click.option("--source-ip", default="127.0.0.1")
def telnet(username: str, password: str, source_ip: str) -> None:
    """Simula intento de login Telnet."""
    result = simulate_telnet_login(username, password)
    if result:
        click.echo(f"[!] Login exitoso desde {source_ip}: {username}:{password}")
        session = create_session(source_ip)
        session.username = username
        session.password = password
        session.authenticated = True
        for cmd in ["whoami", "uname", "ls"]:
            resp = simulate_command(session, cmd)
            click.echo(f"  $ {cmd} -> {resp}")
    else:
        click.echo(f"[-] Login fallido desde {source_ip}: {username}:{password}")


@cli.command()
@click.option("--path", default="/")
@click.option("--device", default="ip_camera")
def http(path: str, device: str) -> None:
    """Simula petición HTTP al honeypot."""
    resp = simulate_http_request(path, device)
    click.echo(f"[+] HTTP {resp.status_code}")
    for k, v in resp.headers.items():
        click.echo(f"  {k}: {v}")
    click.echo(f"  Body: {resp.body[:200]}")


@cli.command()
@click.option("--topic", default="device/status")
@click.option("--payload", default="online")
def mqtt(topic: str, payload: str) -> None:
    """Simula mensaje MQTT."""
    msg = simulate_mqtt_message(topic, payload)
    click.echo(f"[+] MQTT: {msg.topic} -> {msg.payload}")

    status = simulate_broker_status()
    click.echo(f"[+] Broker: {status['broker']} v{status['version']}")
    click.echo(f"  Clients: {status['clients_connected']}, Messages: {status['messages_received']}")


@cli.command()
def credentials() -> None:
    """Lista credenciales por defecto conocidas."""
    creds = get_default_credentials()
    click.echo(f"[*] Credenciales por defecto: {len(creds)}")
    for c in creds:
        click.echo(f"  {c['username']}:{c['password']}")


@cli.command()
def attack_types() -> None:
    """Lista tipos de ataque detectados."""
    types = get_attack_types()
    click.echo(f"[*] Tipos de ataque: {len(types)}")
    for t in types:
        level = get_threat_level(t)
        click.echo(f"  [{level}] {t}")


@cli.command()
@click.option("--commands", required=True, help="Comandos separados por coma")
@click.option("--source-ip", default="127.0.0.1")
def classify(commands: str, source_ip: str) -> None:
    """Clasifica ataques desde comandos."""
    cmd_list = [c.strip() for c in commands.split(",")]
    classifications = classify_attack(cmd_list, source_ip)
    click.echo(f"[*] Clasificaciones: {len(classifications)}")
    for c in classifications:
        click.echo(f"  [{c.severity}] {c.attack_type}: {c.description} ({c.mitre_id})")


@cli.command()
@click.option("--output", default="reporte")
@click.option("--format", "fmt", type=click.Choice(["json", "both"]), default="json")
def report(output: str, fmt: str) -> None:
    """Generar reporte."""
    report_obj = HoneypotReport(device_type="ip_camera")
    report_obj.findings.append(HoneypotFinding(
        category="default_credentials", detail="Credenciales admin:admin detectadas",
        severity="Alto", source_ip="192.168.1.100",
    ))
    report_obj.build_summary()
    if fmt in ("json", "both"):
        p = export_json(report_obj, f"{output}.json")
        click.echo(f"[+] Reporte JSON: {p}")


def main() -> None:
    cli()
