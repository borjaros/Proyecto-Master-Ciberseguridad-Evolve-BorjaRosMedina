# Informe de Análisis de Seguridad
## IDS Corporativo pfSense + Snort — Proyecto 3
### BERMA Automatización e Ingeniería S.L. | Mayo 2026 | Confidencial

---

## 1. Resumen Ejecutivo

Este informe documenta el despliegue y validación de un sistema de detección de intrusiones (IDS) sobre la infraestructura de BERMA Automatización e Ingeniería S.L., empresa de ingeniería industrial con sede en Getafe, Madrid, especializada en sistemas SCADA y programación de PLCs para clientes de los sectores agua, química y alimentaria.

El proyecto materializa las recomendaciones del análisis de riesgos Magerit v3 realizado en el Proyecto 2 del portfolio, concretamente las amenazas asociadas a los activos 3 (red IT/OT), 4 (PLCs Siemens S7-1500), 8 (HMI Siemens TP1200) y 2 (acceso remoto TeamViewer sin MFA).

| Métrica | Valor |
|---------|-------|
| Total alertas detectadas | 194 |
| Tipos de regla disparados | 7 |
| Duración del ejercicio | 5 horas 34 minutos |
| Reglas personalizadas BERMA | 9 |
| IP atacante principal | 192.168.100.100 (83,9% alertas) |
| IP víctima | 10.10.10.50 |

Los resultados confirman que la infraestructura actual de BERMA carece de los controles mínimos necesarios para detectar y responder a ataques de reconocimiento y fuerza bruta. Un atacante con acceso a la red corporativa puede enumerar todos los activos IT y OT en menos de cinco minutos sin encontrar resistencia operativa.

---

## 2. Contexto de la Organización

### 2.1 Perfil de BERMA

BERMA Automatización e Ingeniería S.L. es una empresa de ingeniería industrial fundada en 2011 con sede en Getafe, Madrid. Cuenta con 19 empleados y 2 autónomos colaboradores, con una facturación anual de 2,3 millones de euros. Su actividad principal incluye:

- Diseño e implementación de sistemas SCADA
- Programación de PLCs Siemens S7-1500 y Allen-Bradley
- Integración de sistemas MES y ERP mediante OPC-UA y Modbus
- Mantenimiento remoto 24/7 de sistemas de control industrial para 23 clientes

### 2.2 Nivel de Madurez de Seguridad

Nivel 2 de 5. Controles básicos implantados sin enfoque proactivo ni monitorización.

**Capacidades existentes:**
- Antivirus ESET en servidores, Windows Defender en endpoints
- Backup nocturno automático sin verificación de restauración
- Cuentas de Active Directory individuales

**Carencias críticas identificadas en Magerit (Proyecto 2):**
- Ausencia total de segmentación entre red IT corporativa y red OT industrial
- Ningún servicio de acceso remoto tiene MFA habilitado (TeamViewer, VPN, M365)
- Sin monitorización centralizada ni IDS/IPS de ningún tipo
- HMI Siemens TP1200 con credenciales por defecto y acceso web habilitado
- PLCs S7-1500 con firmware sin actualizar desde 2021

---

## 3. Descripción del Laboratorio

### 3.1 Arquitectura de Red

El laboratorio reproduce la topología de red de BERMA en un entorno virtualizado sobre VirtualBox. pfSense actúa como firewall perimetral con Snort integrado, interceptando y analizando todo el tráfico entre la red del atacante y la red interna corporativa.

| Componente | Función | IP | Red | Tecnología |
|------------|---------|----|----|------------|
| pfSense VM | Firewall + IDS perimetral | 10.10.10.1 / 192.168.100.1 | LAN + OPT1 | pfSense CE 2.7 + Snort |
| VM Víctima | Servidor corporativo BERMA | 10.10.10.50 | LAN host-only | Ubuntu Server + Apache2 |
| Kali Linux | Plataforma de ataque | 192.168.100.100 | OPT1 wan-lab | Nmap / Hydra / Nikto |
| Windows Host | Administración y análisis | 10.10.10.254 | LAN host-only | VirtualBox + Python 3 |

### 3.2 Stack Tecnológico

- pfSense CE 2.7 con tres interfaces: WAN (NAT), LAN (host-only) y OPT1 (internal wan-lab)
- Snort desplegado en interfaz LAN con reglas GPLv2 Community y 9 reglas personalizadas BERMA
- Kali Linux con Nmap 7.x, Hydra y Nikto para ataques controlados
- Python 3 con pandas y matplotlib para análisis automatizado de logs
- Wireshark/tshark para captura de evidencias forenses

### 3.3 Reglas Snort Personalizadas BERMA

| SID | Regla | Protocolo / Puerto | Justificación |
|-----|-------|-------------------|---------------|
| 9000001 | BERMA-001 SSH Brute Force | TCP / 22 | VPN y TeamViewer sin MFA con credenciales compartidas |
| 9000002 | BERMA-002 Port Scan | TCP / Any | Red plana IT/OT: un escaneo expone todos los activos |
| 9000003 | BERMA-003 HMI Web Access | TCP / 80 | HMI TP1200 con credenciales por defecto y web habilitado |
| 9000004 | BERMA-004 Nikto Scanner | TCP / 80 | WinCC V7.5 expone interfaz web con vulnerabilidades |
| 9000005 | BERMA-005 Modbus TCP | TCP / 502 | Modbus en red IT = acceso no autorizado a OT |
| 9000006 | BERMA-006 S7comm Siemens | TCP / 102 | Protocolo PLC nunca debe originarse desde IPs externas |
| 9000007 | BERMA-007 Nmap Aggressive | TCP / Any | Flags SFP/SFU inusuales preceden a explotación dirigida |
| 9000008 | BERMA-008 ICMP Echo Request | ICMP | Ping individual desde red no confiable = reconocimiento |
| 9000009 | BERMA-009 ICMP Ping Sweep | ICMP | Cinco pings en tres segundos = enumeración automatizada |

---

## 4. Metodología de Ataque

Los ataques se ejecutaron desde Kali Linux (192.168.100.100) atravesando pfSense hacia la VM víctima (10.10.10.50) replicando la cadena de ataque de un actor que ha conseguido acceso a la red corporativa de BERMA a través de la VPN sin MFA o una sesión de TeamViewer comprometida.

### 4.1 Fase 1 — Reconocimiento de Red (Nmap)

Se ejecutaron cuatro perfiles progresivos:

```bash
# Descubrimiento de hosts activos
nmap -sn -Pn 10.10.10.0/24

# Identificación de puertos abiertos
nmap -sS -Pn 10.10.10.50

# Detección de versiones y sistema operativo
nmap -sV -O -Pn 10.10.10.50

# Máximo reconocimiento con scripts NSE
nmap -A -Pn 10.10.10.50
```

En un entorno real de BERMA el ping sweep revelaría PLCs, HMIs, servidores y endpoints en el mismo segmento sin ninguna barrera intermedia.

### 4.2 Fase 2 — Fuerza Bruta SSH (Hydra)

```bash
hydra -l root -P /tmp/passwords.txt 10.10.10.50 ssh -t 4 -V
```

Replica el vector más crítico de BERMA: sin MFA ni política de bloqueo de cuentas, los intentos de fuerza bruta no encuentran ningún control que los detenga.

### 4.3 Fase 3 — Escaneo de Aplicación Web (Nikto)

```bash
nikto -h http://10.10.10.50
```

En producción apuntaría a la interfaz web del HMI Siemens TP1200 o al servidor WinCC V7.5, detectando ficheros expuestos, cabeceras de seguridad ausentes y vulnerabilidades conocidas.

---

## 5. Análisis de Alertas Detectadas

### 5.1 Distribución por Tipo de Regla

| Regla | Descripción | Protocolo | Alertas | Severidad |
|-------|-------------|-----------|---------|-----------|
| BERMA-TEST | ICMP test de laboratorio | ICMP | 101 | 3 - Bajo |
| WEB-COMUNIDAD | Reglas web comunidad Snort | TCP | 30 | 2 - Medio |
| SNORT-COMUNIDAD | Reglas comunidad genéricas | Multi | 27 | 2 - Medio |
| BERMA-007 | Nmap Aggressive Scan | TCP | 16 | 2 - Medio |
| BERMA-004 | Nikto Web Scanner | TCP | 9 | 2 - Medio |
| OTRAS | Reglas adicionales | Multi | 11 | Variable |
| **TOTAL** | | | **194** | |

### 5.2 Distribución por IP

| IP | Rol | Alertas | Segmento | Porcentaje |
|----|-----|---------|----------|------------|
| 192.168.100.100 | Kali Linux atacante | 163 | OPT1 wan-lab | 83,9% |
| 10.10.10.50 | VM víctima | 23 | LAN host-only | 11,8% |
| 192.168.100.1 | pfSense OPT1 | 5 | OPT1 wan-lab | 2,6% |

### 5.3 Análisis por Tipo de Ataque

**Reconocimiento ICMP (101 alertas — BERMA-TEST)**

En un entorno de producción de BERMA, 101 pings procedentes de una IP no autorizada representaría una anomalía clara de reconocimiento activo. La regla BERMA-009 de ping sweep dispararía con cinco pings en tres segundos, generando una alerta de severidad media que debería escalar automáticamente a un operador de seguridad.

**Reconocimiento avanzado Nmap (16 alertas — BERMA-007)**

Las 16 alertas corresponden al escaneo aggressive que usa flags TCP inusuales (SFP, SFU) que no aparecen en tráfico legítimo. En BERMA este patrón es especialmente peligroso porque el switch Cisco SG350 no tiene VLANs, lo que significa que Nmap desde cualquier punto de la red corporativa alcanza los PLCs S7-1500, el HMI TP1200 y WinCC sin ninguna barrera intermedia.

**Escaneo web y reglas de comunidad (39 alertas)**

Las 30 alertas de WEB-COMUNIDAD y las 9 de BERMA-004 corresponden al tráfico de Nikto. En producción apuntarían a la interfaz web del HMI TP1200 o al servidor WinCC V7.5, pudiendo identificar el panel de administración de un sistema de control industrial accesible sin autenticación fuerte.

**Reglas OT no disparadas (BERMA-005 y BERMA-006)**

Las reglas de detección de tráfico Modbus (puerto 502) y S7comm Siemens (puerto 102) no generaron alertas porque la VM víctima del laboratorio no tiene estos servicios activos. En un despliegue real sobre la infraestructura de BERMA estas serían las reglas más críticas: cualquier tráfico hacia los puertos 502 o 102 cruzando desde la red IT hacia la red OT comprometería los procesos industriales de los 23 clientes del sector agua, química y alimentaria.

---

## 6. Recomendaciones

| ID | Recomendación | Activo Magerit | Prioridad |
|----|---------------|----------------|-----------|
| REC-01 | Segmentación IT/OT con VLAN y firewall intermedio | Activo 3 | Crítica |
| REC-02 | MFA en TeamViewer, VPN y Microsoft 365 | Activos 2 y 9 | Alta |
| REC-03 | IDS/IPS en perímetro con reglas OT específicas | Activos 3 y 4 | Alta |
| REC-04 | Cifrado de disco en portátiles de campo | Activo 5 | Alta |
| REC-05 | Actualizar firmware PLCs S7-1500 (sin actualizar desde 2021) | Activo 4 | Alta |
| REC-06 | Cambiar credenciales por defecto en HMI TP1200 | Activo 8 | Alta |
| REC-07 | Centralizar logs en SIEM con alertas automáticas | Global | Media |
| REC-08 | Cifrar backups NAS QNAP y verificar restauración | Activo 7 | Media |
| REC-09 | Control de versiones del código fuente TIA Portal | Activo 4 | Media |
| REC-10 | Política formal de seguridad documentada | Global | Media |

### Hoja de Ruta

**Corto plazo (0 a 3 meses):** REC-02, REC-06, REC-05. Coste bajo, impacto inmediato sobre los vectores más explotados.

**Medio plazo (3 a 9 meses):** REC-01, REC-03, REC-04. Requieren planificación técnica pero son fundamentales para la continuidad del negocio.

**Largo plazo (9 a 18 meses):** REC-07, REC-08, REC-09, REC-10. Consolidan el modelo de seguridad y habilitan la respuesta a incidentes estructurada.

---

## 7. Conclusiones

El ejercicio ha demostrado empíricamente las hipótesis de riesgo formuladas en el análisis Magerit del Proyecto 2. Un atacante que acceda a la red corporativa de BERMA puede:

- Enumerar toda la infraestructura IT y OT en menos de cinco minutos mediante Nmap sin encontrar ningún control de detección activo
- Identificar el HMI Siemens TP1200 con acceso web en credenciales por defecto accesible directamente desde la red corporativa
- Alcanzar los PLCs S7-1500 sin atravesar ningún firewall gracias a la ausencia de segmentación entre el switch corporativo y el switch industrial
- Lanzar ataques de fuerza bruta SSH sin límite de intentos ni bloqueo de cuenta

La implementación del IDS con pfSense y Snort documentada en este proyecto constituye el primer control de detección real implantado en BERMA. Las nueve reglas personalizadas demuestran que es posible detectar estos ataques con recursos limitados y sin inversión en herramientas comerciales, siempre que exista conocimiento del entorno y criterio técnico en la definición de las reglas.

La continuación natural de este trabajo es el **Proyecto 4** del portfolio, que implementará una PKI corporativa con CA raíz e intermedia, VPN WireGuard con certificados individuales por usuario y gestión de revocación mediante CRL, abordando directamente las carencias de autenticación identificadas en este informe.

---

*Documento generado como parte del Portfolio de Ciberseguridad — Clasificación CONFIDENCIAL — Mayo 2026*
