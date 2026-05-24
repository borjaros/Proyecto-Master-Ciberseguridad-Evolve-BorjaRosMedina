# Documentación de Reglas de Firewall pfSense
# BERMA Automatización e Ingeniería S.L. - fw01-berma.local
# Proyecto 3 Portfolio Ciberseguridad

---

## Configuración General

Hostname: fw01-berma
Domain: berma.local
Versión: pfSense CE 2.7.x

---

## Interfaces

| Interfaz | Adaptador | Red | IP pfSense | Función |
|----------|-----------|-----|------------|---------|
| WAN | NAT (VirtualBox) | 10.0.2.0/24 | DHCP | Internet para actualizaciones Snort |
| LAN | Host-only | 10.10.10.0/24 | 10.10.10.1 | Red interna protegida / víctima |
| OPT1 (WAN-LAB-ATACANTE) | Internal wan-lab | 192.168.100.0/24 | 192.168.100.1 | Red atacante Kali Linux |

---

## Reglas por Interfaz

### WAN

Sin reglas manuales. pfSense bloquea todo el tráfico entrante por WAN por defecto.
Solo permite tráfico de salida para descarga de reglas Snort y actualizaciones del sistema.

---

### LAN

Reglas creadas automáticamente por pfSense al configurar la interfaz LAN.

**Regla anti-lockout (automática)**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | TCP |
| Source | any |
| Destination | LAN address |
| Port | 443, 80 |
| Descripción | Anti-lockout: acceso garantizado al web GUI de pfSense |

**Regla LAN to any (automática)**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | any |
| Source | LAN subnet |
| Destination | any |
| Descripción | Permite tráfico de salida desde la red interna |

---

### OPT1 WAN-LAB-ATACANTE

Reglas configuradas manualmente para permitir el tráfico de ataque del laboratorio.
**Nota de laboratorio**: estas reglas son deliberadamente permisivas para permitir
que los ataques de Kali alcancen la víctima y sean detectados por Snort.
En un entorno de producción se restringirían por IP origen, puerto destino y protocolo.

**Regla 1 - TCP Ataques**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | TCP |
| Source | Network 192.168.100.0/24 |
| Destination | Network 10.10.10.0/24 |
| Port destino | any |
| Descripción | BERMA-LAB TCP Kali hacia víctima |

**Regla 2 - ICMP a víctima**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | ICMP |
| ICMP Type | any |
| Source | Network 192.168.100.0/24 |
| Destination | Network 10.10.10.0/24 |
| Descripción | BERMA-LAB ICMP Kali hacia víctima |

**Regla 3 - ICMP a pfSense**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | ICMP |
| ICMP Type | any |
| Source | any |
| Destination | Single host 192.168.100.1 |
| Descripción | BERMA-LAB ICMP Kali hacia pfSense OPT1 |

**Regla 4 - LAN subnet**

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | any |
| Source | LAN subnet |
| Destination | any |
| Descripción | LAN to any default |

---

## Configuración DHCP

### LAN
- Rango: 10.10.10.100 - 10.10.10.200
- Gateway: 10.10.10.1
- DNS: 8.8.8.8, 1.1.1.1

### OPT1 WAN-LAB-ATACANTE
- Rango: 192.168.100.100 - 192.168.100.200
- Gateway: 192.168.100.1

---

## Configuración Snort

### Interfaces monitorizadas

| Interfaz | Nombre | Reglas activas |
|----------|--------|----------------|
| LAN | LAN-BERMA-IDS | GPLv2 Community + 9 reglas BERMA personalizadas |
| OPT1 | OPT1-ATACANTE-KALI | GPLv2 Community + 9 reglas BERMA personalizadas |

### Parámetros globales
- Block Offenders: Deshabilitado (laboratorio, no bloquear IPs atacantes)
- Send Alerts to System Log: Habilitado
- Update Interval: 12 horas
- Reglas de comunidad: Snort GPLv2 Community Rules

### Archivo de reglas personalizadas
Ver `rules/berma-custom.rules` para el contenido completo con comentarios de justificación.
