"""Tests para mqtt_honeypot."""

from iot_honeypot.honeypot.mqtt_honeypot import (
    simulate_mqtt_message, get_iot_topics, simulate_broker_status
)


def test_mqtt_message():
    msg = simulate_mqtt_message("device/status", "online")
    assert msg.topic == "device/status"
    assert msg.payload == "online"


def test_iot_topics():
    topics = get_iot_topics()
    assert len(topics) > 0
    assert "device/status" in topics


def test_broker_status():
    status = simulate_broker_status()
    assert "broker" in status
    assert "clients_connected" in status
