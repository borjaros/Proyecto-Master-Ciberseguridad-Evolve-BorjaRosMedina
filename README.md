# Proyecto 3 - IDS Corporativo pfSense + Snort + Python

**Portfolio Ciberseguridad** | Proyecto 3 de 5 | Mayo 2026

![pfSense](https://img.shields.io/badge/pfSense-CE_2.7-blue)
![Snort](https://img.shields.io/badge/Snort-IDS-red)
![Python](https://img.shields.io/badge/Python-3.x-yellow)
![Kali](https://img.shields.io/badge/Kali-Linux-purple)

---

## Contexto

Este proyecto forma parte de un portfolio de ciberseguridad de cinco proyectos construido sobre la empresa ficticia **BERMA Automatización e Ingeniería S.L.**, empresa industrial de Getafe (Madrid) con 19 empleados y entorno OT/IT sin segmentar que atiende 23 clientes en sectores agua, química y alimentaria.

El proyecto materializa las recomendaciones del [análisis de riesgos Magerit v3](../proyecto2-magerit-berma) realizado en el Proyecto 2, concretamente las amenazas sobre los activos de red IT/OT (activo 3), PLCs Siemens S7-1500 (activo 4), HMI Siemens TP1200 (activo 8) y acceso remoto TeamViewer sin MFA (activo 2).

---

## Arquitectura del Laboratorio

```
┌─────────────────────┐         ┌──────────────────────┐         ┌──────────────────────────┐
│   RED ATACANTE      │         │      PFSENSE         │         │    RED INTERNA BERMA     │
│   wan-lab           │         │   fw01-berma.local   │         │    host-only             │
│   192.168.100.0/24  │         │                      │         │    10.10.10.0/24         │
│                     │         │  OPT1  ←→  LAN       │         │                          │
│  ┌──────────────┐   │──────►  │  .1        .1        │ ──────► │  ┌──────────────────┐   │
│  │  Kali Linux  │   │  ataque │                      │ trafico │  │  Ubuntu Server   │   │
│  │ 192.168.100  │   │         │  Snort activo en LAN │         │  │  10.10.10.50     │   │
│  │    .100      │   │         │  9 reglas BERMA      │         │  │  Apache2 + SSH   │   │
│  └──────────────┘   │         │                      │         │  └──────────────────┘   │
│  Nmap | Hydra       │         │  WAN → NAT           │         │                          │
│  Nikto | Wireshark  │         │  (actualizaciones)   │         │  ┌──────────────────┐   │
└─────────────────────┘         └──────────────────────┘         │  │  Windows Host    │   │
                                                                  │  │  10.10.10.254    │   │
                                                                  │  │  Admin + Python  │   │
                                                                  │  └──────────────────┘   │
                                                                  └──────────────────────────┘
```

Diagrama completo en [`diagrams/arquitectura-laboratorio.drawio`](diagrams/arquitectura-laboratorio.drawio)

---

## Reglas Snort Personalizadas BERMA

Las reglas genéricas de comunidad detectan ataques conocidos. Estas nueve reglas detectan ataques específicos al entorno OT/IT de BERMA:

| Regla | Detección | Justificación BERMA |
|-------|-----------|---------------------|
| BERMA-001 | SSH Brute Force | VPN y TeamViewer sin MFA con credenciales compartidas entre técnicos |
| BERMA-002 | Port Scan horizontal | Red plana IT/OT sin VLANs: un escaneo expone PLCs, HMIs y servidores |
| BERMA-003 | HMI Web Access | HMI Siemens TP1200 con credenciales por defecto y acceso web habilitado |
| BERMA-004 | Nikto Web Scanner | WinCC V7.5 expone interfaz web. Nikto detecta vulnerabilidades en SCADA web |
| BERMA-005 | Modbus TCP (puerto 502) | Cualquier Modbus cruzando la red IT indica acceso directo no autorizado a OT |
| BERMA-006 | S7comm Siemens (puerto 102) | Protocolo PLC Siemens nunca debe originarse desde IPs externas o no autorizadas |
| BERMA-007 | Nmap Aggressive Scan | Flags TCP inusuales (SFP/SFU) que preceden habitualmente a explotación dirigida |
| BERMA-008 | ICMP Echo Request | Ping individual desde red no confiable indica reconocimiento activo |
| BERMA-009 | ICMP Ping Sweep | Cinco pings en tres segundos indican enumeración automatizada de hosts |

Archivo completo en [`rules/berma-custom.rules`](rules/berma-custom.rules)

---

## Script de Análisis Python

Parsea los logs exportados de pfSense/Snort y genera tres visualizaciones automáticas.

### Instalación

```bash
pip install pandas matplotlib
```

### Uso

```bash
# Con archivos reales exportados de pfSense
python scripts/analisis_snort_berma.py --lan captures/alertas_lan.csv

# Con ambas interfaces
python scripts/analisis_snort_berma.py --lan captures/alertas_lan.csv --opt1 captures/alertas_opt1.csv

# Modo demo con datos simulados (sin necesidad de pfSense)
python scripts/analisis_snort_berma.py --demo
```

### Salida

El script genera en `graficas_berma/`:

- `alertas_por_tipo_<interfaz>.png` - Distribución de alertas por regla Snort
- `timeline_<interfaz>.png` - Línea temporal de ataques por minuto con pico marcado
- `ips_atacantes_<interfaz>.png` - Top de IPs atacantes por número de alertas

---

## Hallazgos Principales

Del análisis de 194 alertas capturadas durante 5 horas y 34 minutos:

- **Red plana IT/OT confirmada**: Nmap desde la red del atacante alcanzó directamente la VM víctima sin encontrar ninguna barrera intermedia, lo que en producción equivale a acceso directo a PLCs S7-1500 y HMI TP1200.
- **Reconocimiento sin fricción**: Los cuatro perfiles de Nmap completaron la enumeración completa del segmento sin activar ningún bloqueo automático, en 194 alertas detectadas pero ninguna respondida.
- **Fuerza bruta SSH sin límite**: Hydra ejecutó intentos de autenticación repetidos sin restricción de intentos ni bloqueo de cuenta, validando la ausencia de política de contraseñas robusta.
- **Reglas OT no disparadas**: BERMA-005 (Modbus) y BERMA-006 (S7comm) no generaron alertas porque el laboratorio no emula servicios OT reales. En producción sobre la infraestructura de BERMA estas serían las reglas más críticas.
- **Cobertura del 100% de los ataques ejecutados**: Todos los ataques lanzados desde Kali generaron al menos una alerta en Snort, confirmando que las reglas personalizadas cubren los vectores relevantes para el entorno.

---

## Estructura del Repositorio

```
proyecto3-ids-berma/
├── README.md
├── rules/
│   └── berma-custom.rules          # Reglas Snort personalizadas con comentarios
├── scripts/
│   └── analisis_snort_berma.py     # Script Python de análisis de logs
├── config/
│   └── pfsense-firewall-rules.md   # Documentación de reglas de firewall pfSense
├── reports/
│   └── informe-ids-berma.md        # Informe técnico completo
├── captures/
│   ├── alertas_lan.csv             # Logs reales exportados de Snort LAN
│   └── captura-ataques-berma.pcap  # Captura Wireshark de los ataques
├── graficas/
│   ├── alertas_por_tipo_LAN-BERMA-IDS.png
│   ├── timeline_LAN-BERMA-IDS.png
│   └── ips_atacantes_LAN-BERMA-IDS.png
└── diagrams/
    └── arquitectura-laboratorio.drawio
```

---

## Stack Tecnológico

pfSense CE 2.7 | Snort con reglas GPLv2 | Kali Linux | Nmap 7.x | Hydra | Nikto | Wireshark | Python 3 | pandas | matplotlib | VirtualBox

---

