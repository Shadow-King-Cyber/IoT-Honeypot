"""Clasificador de ataques — clasifica patrones de ataque."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AttackClassification:
    """Clasificación de un ataque detectado."""
    attack_type: str
    severity: str
    confidence: str
    description: str
    mitre_id: str


ATTACK_PATTERNS: dict[str, dict] = {
    "command_injection": {
        "severity": "Critico",
        "mitre": "T1059",
        "description": "Intento de inyección de comandos",
        "keywords": ["; cat", "| cat", "&&", "$(", "`"],
    },
    "brute_force": {
        "severity": "Alto",
        "mitre": "T1110",
        "description": "Múltiples intentos de login fallidos",
        "keywords": ["login", "password", "auth", "credential"],
    },
    "credential_stuffing": {
        "severity": "Alto",
        "mitre": "T1110.004",
        "description": "Uso de credenciales filtradas en otros servicios",
        "keywords": ["admin", "root", "password"],
    },
    "scanning": {
        "severity": "Medio",
        "mitre": "T1046",
        "description": "Escaneo de puertos o servicios",
        "keywords": ["scan", "port", "probe"],
    },
    "reconnaissance": {
        "severity": "Bajo",
        "mitre": "T1592",
        "description": "Recolectar información sobre el dispositivo",
        "keywords": ["whoami", "uname", "id"],
    },
}


def classify_attack(commands: list[str], source_ip: str) -> list[AttackClassification]:
    """Clasifica ataques basándose en comandos ejecutados."""
    classifications: list[AttackClassification] = []

    for cmd in commands:
        cmd_lower = cmd.lower()
        for attack_type, info in ATTACK_PATTERNS.items():
            if any(kw in cmd_lower for kw in info["keywords"]):
                classifications.append(AttackClassification(
                    attack_type=attack_type,
                    severity=info["severity"],
                    confidence="high",
                    description=info["description"],
                    mitre_id=info["mitre"],
                ))
                break

    return classifications


def get_attack_types() -> list[str]:
    """Devuelve los tipos de ataque detectados."""
    return list(ATTACK_PATTERNS.keys())
