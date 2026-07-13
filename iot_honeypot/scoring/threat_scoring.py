"""Scoring de amenazas — nivel de amenaza por tipo de ataque."""

from __future__ import annotations


THREAT_MAP: dict[str, str] = {
    "brute_force": "Alto",
    "credential_stuffing": "Alto",
    "command_injection": "Critico",
    "scanning": "Medio",
    "reconnaissance": "Bajo",
    "default_credentials": "Alto",
    "lateral_movement": "Critico",
}


def get_threat_level(attack_type: str) -> str:
    """Devuelve el nivel de amenaza para un tipo de ataque."""
    return THREAT_MAP.get(attack_type, "Info")


def calculate_threat_score(attacks: list[str]) -> dict[str, int | str]:
    """Calcula el score total de amenazas."""
    summary: dict[str, int] = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0, "Info": 0}
    for attack in attacks:
        level = get_threat_level(attack)
        if level in summary:
            summary[level] += 1

    values = {"Critico": 4, "Alto": 3, "Medio": 2, "Bajo": 1, "Info": 0}
    max_val = max((values[level] * count for level, count in summary.items() if count > 0), default=0)
    overall = {v: k for k, v in values.items()}.get(max_val, "Info")

    return {"summary": summary, "overall": overall}
