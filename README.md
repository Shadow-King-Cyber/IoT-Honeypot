# IoT-Honeypot

Honeypot IoT que emula dispositivos vulnerables para capturar y analizar tráfico de ataque.

> **ADVERTENCIA**: Solo para investigación de seguridad autorizada. No exponer en producción sin supervisión.

## Características

- **Telnet honeypot** con credenciales por defecto conocidas
- **HTTP honeypot** emulando cámaras IP, routers, gateways
- **MQTT honeypot** con topics IoT comunes
- **Clasificador de ataques** con mapeo MITRE ATT&CK
- **Scoring de amenazas** por tipo de ataque
- **CLI Click** para simulación y análisis

## Instalación

```bash
git clone https://github.com/Shadow-King-Cyber/IoT-Honeypot.git
cd IoT-Honeypot
pip install -r requirements.txt
```

## Uso

```bash
# Simular login Telnet
iot-honeypot telnet --username admin --password admin

# Simular petición HTTP
iot-honeypot http --path / --device ip_camera

# Simular mensaje MQTT
iot-honeypot mqtt --topic device/status --payload online

# Listar credenciales por defecto
iot-honeypot credentials

# Clasificar ataques
iot-honeypot classify --commands "whoami,uname,cat /etc/passwd"
```

## Licencia

MIT License — Shadow-King-Cyber
