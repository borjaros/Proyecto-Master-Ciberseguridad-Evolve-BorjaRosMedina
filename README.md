# Proyecto 4 — PKI Corporativa BERMA + VPN WireGuard

## Contexto

BERMA Automatización e Ingeniería S.L. (Getafe, Madrid) es una empresa de ingeniería industrial que opera sistemas SCADA críticos con acceso remoto de técnicos de campo. El análisis de riesgos Magerit v3 realizado en el Proyecto 2 identificó la ausencia de autenticación de certificados y la falta de segmentación de identidad digital como brechas críticas de seguridad.

Este proyecto implementa desde cero la infraestructura PKI que resuelve esas brechas: una jerarquía de CAs propia, VPN con autenticación por certificado y gestión completa del ciclo de vida de certificados con revocación.

---

## Arquitectura PKI

```
BERMA Root CA (RSA 4096 · SHA-256 · Válida 10 años)
│  Clave privada cifrada con AES-256 · Almacenamiento offline
│
└── BERMA Intermediate CA (RSA 2048 · SHA-256 · Válida 5 años)
    │  pathlen:0 → no puede crear sub-CAs
    │  CRL: http://192.168.100.10/crl/intermediate.crl
    │
    ├── berma-ca.local          (Servidor · serverAuth · 375 días)
    ├── tecnico01@berma.local   (Cliente  · clientAuth · 375 días)
    └── [Certificados adicionales vía pki_manager.py]
```

---

## Jerarquía de confianza

La PKI implementa dos niveles deliberadamente:

- **CA Raíz** → se mantiene offline. Solo sale para firmar nuevas CAs Intermedias.
- **CA Intermedia** → opera online. Firma todos los certificados finales.

Esta separación garantiza que si la CA Intermedia es comprometida, puede revocarse y reemplazarse sin tocar la CA Raíz ni los dispositivos que ya confían en ella.

---

## Infraestructura del laboratorio

| VM | Hostname | IP Red Interna | Rol |
|----|----------|---------------|-----|
| berma-ca | apachesito | 192.168.100.10 | CA Raíz + CA Intermedia + Apache CRL |
| berma-vpn | wireguard | 192.168.100.20 | Cliente WireGuard |

**VPN WireGuard:**
- Servidor: `berma-ca` → `10.0.0.1`
- Cliente: `berma-vpn` → `10.0.0.2`
- Puerto: UDP 51820

---

## Stack tecnológico

| Herramienta | Versión | Uso |
|-------------|---------|-----|
| OpenSSL | 3.x | Toda la infraestructura PKI |
| WireGuard | kernel nativo | VPN cifrada |
| Apache2 | 2.4.x | Distribución de CRL por HTTP |
| Python 3 | 3.x | Automatización emisión/revocación |
| VirtualBox | 7.x | Laboratorio virtualizado |
| Ubuntu Server | 22.04 LTS | SO de ambas VMs |

---

## Uso del script de automatización

```bash
# Emitir certificado de cliente
sudo python3 scripts/pki_manager.py emit --name tecnico02 --type client --email tecnico02@berma.local

# Emitir certificado de servidor
sudo python3 scripts/pki_manager.py emit --name vpn-server --type server

# Revocar certificado
sudo python3 scripts/pki_manager.py revoke --name tecnico02 --reason keyCompromise

# Listar todos los certificados y su estado
sudo python3 scripts/pki_manager.py list

# Regenerar y publicar la CRL
sudo python3 scripts/pki_manager.py update-crl
```

---

## Decisiones criptográficas

Documentadas en detalle en [`docs/decisiones-criptograficas.md`](docs/decisiones-criptograficas.md).

Resumen ejecutivo:

| Decisión | Elección | Razón principal |
|----------|----------|----------------|
| Algoritmo CA Raíz | RSA 4096 | Activo crítico de larga vida, coste computacional irrelevante |
| Algoritmo CA Intermedia | RSA 2048 | Suficiente seguridad para validez de 5 años, mejor rendimiento |
| Hash | SHA-256 | SHA-1 roto desde 2017, estándar actual |
| Validez certificados finales | 375 días | Límite de 398 días impuesto por navegadores desde 2020 |
| Jerarquía | 2 niveles | CA Raíz offline, revocación parcial posible sin reemplazar raíz |
| Protección clave raíz | AES-256 + passphrase | Clave robada sin passphrase = inutilizable |

---

## CRL vs OCSP

Comparativa completa en [`docs/crl-vs-ocsp.md`](docs/crl-vs-ocsp.md).

Se implementó CRL en lugar de OCSP por:
- Menor complejidad de infraestructura (archivo estático vs servicio 24/7).
- Mayor privacidad (verificación local, la CA no registra consultas).
- Compatibilidad total con el entorno OT de BERMA (dispositivos Siemens legacy).

---

## PKI propia vs Let's Encrypt vs CA Comercial

| Escenario | Solución correcta |
|-----------|------------------|
| Web pública con HTTPS | Let's Encrypt |
| Servicios internos sin internet | **PKI Propia** ← este proyecto |
| mTLS entre servicios o dispositivos | **PKI Propia** |
| E-commerce / banca online (EV) | CA Comercial |
| Cumplimiento PCI-DSS / eIDAS | CA Comercial |

BERMA opera en red privada con autenticación mutua de técnicos de campo → PKI propia es la única opción técnicamente correcta.

---

## Estructura del repositorio

```
proyecto4-pki-berma/
├── README.md
├── .gitignore
├── diagrams/
│   ├── pki-hierarchy.svg
│   └── pki-hierarchy.png
├── config/
│   ├── root-ca/
│   │   └── openssl.cnf
│   └── intermediate-ca/
│       └── openssl.cnf
├── certs/
│   └── ca-chain.crt
├── scripts/
│   └── pki_manager.py
└── docs/
    ├── decisiones-criptograficas.md
    └── crl-vs-ocsp.md
```

> Las claves privadas nunca se incluyen en el repositorio. Ver `.gitignore`.

---

## Habilidades que valida este proyecto

`PKI Architecture` · `X.509 Certificates` · `OpenSSL` · `Applied Cryptography` · `WireGuard` · `Certificate Lifecycle Management` · `RSA` · `CRL` · `Python Automation`

---

## Proyecto enmarcado en

Portfolio de ciberseguridad orientado al mercado español. Infraestructura ficticia de BERMA Automatización e Ingeniería S.L., empresa de ingeniería industrial con sistemas SCADA en sectores de agua, química y alimentaria.

- **Proyecto 1:** Infraestructura web segura con Apache2, Nginx, BIND9, SSL y Zabbix
- **Proyecto 2:** Análisis de riesgos Magerit v3 + RGPD + NIS2
- **Proyecto 3:** IDS corporativo con pfSense y análisis de tráfico con Python
- **Proyecto 4:** PKI corporativa + VPN WireGuard ← este proyecto
- **Proyecto 5:** Simulación de incidente con Metasploit, MITRE ATT&CK y análisis forense
