"""Tests para audit_logger."""

from iot_honeypot.core.audit_logger import AuditLogger


def test_log(tmp_path):
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    record = logger.log("TELNET_LOGIN", "192.168.1.1", "SUCCESS")
    assert record["action"] == "TELNET_LOGIN"
    assert record["result"] == "SUCCESS"


def test_read_all(tmp_path):
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log("A1", "s1", "OK")
    logger.log("A2", "s2", "OK")
    assert len(logger.read_all()) == 2
