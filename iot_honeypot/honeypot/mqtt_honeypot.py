"""Honeypot MQTT — emula broker MQTT IoT."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MQTTMessage:
    """Mensaje MQTT simulado."""
    topic: str
    payload: str
    qos: int
    retain: bool


# Topics comunes de IoT
IOT_TOPICS = [
    "device/status",
    "sensor/temperature",
    "sensor/humidity",
    "camera/stream",
    "gateway/config",
    "admin/command",
    "device/heartbeat",
    "ota/update",
]


def simulate_mqtt_message(topic: str, payload: str) -> MQTTMessage:
    """Simula la recepción de un mensaje MQTT."""
    return MQTTMessage(
        topic=topic,
        payload=payload,
        qos=0,
        retain=False,
    )


def get_iot_topics() -> list[str]:
    """Devuelve los topics IoT comunes."""
    return IOT_TOPICS.copy()


def simulate_broker_status() -> dict[str, str | int]:
    """Simula el estado del broker MQTT."""
    return {
        "broker": "Mosquitto",
        "version": "2.0.15",
        "clients_connected": 3,
        "messages_received": 1547,
        "uptime": "72h 14m",
    }
