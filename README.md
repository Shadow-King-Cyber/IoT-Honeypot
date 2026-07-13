# IoT-Honeypot

Honeypot IoT que emula dispositivos vulnerables para capturar y analizar tráfico de ataque.

> **ADVERTENCIA**: Solo para investigación de seguridad autorizada. No exponer en producción sin supervisión.

## Características

- **Telnet honeypot** con credenciales por defecto conocidas
- **HTTP honeypot** emulando cámaras IP, routers, gateways
- **MQTT honeypot** con topics IoT comunes
- **Clasificador de ataques** con mapeo MITRE ATT&CK
- **Scoring de amenazas** por tipo de ataque
- **Reportes JSON** con hallazgos y evidencia
- **CLI Click** para simulación y análisis

## Aviso Legal

Esta herramienta se proporciona únicamente con fines educativos y para investigación de seguridad autorizada. El usuario asume toda la responsabilidad de garantizar que cuenta con la autorización adecuada.

**Al usar este software, aceptas que:**
- Solo lo usarás en entornos controlados y autorizados
- No lo expondrás en producción sin supervisión adecuada
- Los autores no asumen responsabilidad por uso indebido

## Requisitos

- Python 3.11+

```bash
git clone https://github.com/Shadow-King-Cyber/IoT-Honeypot.git
cd IoT-Honeypot
pip install -r requirements.txt
```

## Inicio Rápido

```bash
# Simular login Telnet con credenciales por defecto
iot-honeypot telnet --username admin --password admin

# Simular petición HTTP a cámara IP
iot-honeypot http --path / --device ip_camera

# Simular mensaje MQTT
iot-honeypot mqtt --topic device/status --payload online

# Listar credenciales por defecto conocidas
iot-honeypot credentials

# Listar tipos de ataque detectados
iot-honeypot attack-types

# Clasificar comandos sospechosos
iot-honeypot classify --commands "whoami,uname,cat /etc/passwd"
```

## Comandos del CLI

```bash
# Simular intento de login Telnet
iot-honeypot telnet --username admin --password admin --source-ip 192.168.1.100

# Simular petición HTTP
iot-honeypot http --path /env --device ip_camera

# Simular mensaje MQTT
iot-honeypot mqtt --topic device/status --payload online

# Listar credenciales por defecto
iot-honeypot credentials

# Listar tipos de ataque
iot-honeypot attack-types

# Clasificar ataques desde comandos
iot-honeypot classify --commands "whoami,id,uname -a" --source-ip 10.0.0.5

# Generar reporte
iot-honeypot report --output reporte --format json
```

## Estructura del Proyecto

```
IoT-Honeypot/
├── iot_honeypot/
│   ├── honeypot/       # TelnetHoneypot, HTTPHoneypot, MQTTHoneypot
│   ├── detection/      # AttackClassifier con mapeo MITRE ATT&CK
│   ├── scoring/        # ThreatScoring por tipo de ataque
│   ├── reporting/      # Generación de reportes JSON
│   └── ui/             # CLI Click
├── tests/              # Suite de tests con pytest
├── requirements.txt    # Dependencias de Python
├── pyproject.toml      # Configuración del proyecto
└── LICENSE             # Licencia MIT
```

## Ejecutar Tests

```bash
pytest -v
```

## Licencia

MIT License — ver [LICENSE](LICENSE)
