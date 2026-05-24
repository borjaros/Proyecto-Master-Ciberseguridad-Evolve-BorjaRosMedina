# Reglas Snort Personalizadas BERMA
## BERMA Automatización e Ingeniería S.L. — IDS Perimetral
### Proyecto 3 Portfolio Ciberseguridad | Mayo 2026

---

## Contexto

Las siguientes reglas complementan las reglas de comunidad Snort GPLv2 con detecciones
específicas para el entorno OT/IT de BERMA. A diferencia de las reglas genéricas, cada
una de estas reglas tiene justificación directa en la infraestructura real de la empresa:
red IT/OT sin segmentar, acceso remoto sin MFA, HMI con credenciales por defecto y PLCs
con firmware desactualizado.

Todas las reglas usan SIDs en el rango 9000001-9000099, reservado para reglas locales
según las directrices de Snort.

---

## Clasificación de Severidad

| Nivel | Valor | Descripción |
|-------|-------|-------------|
| Alta | 1 | Compromiso activo o acceso no autorizado confirmado |
| Media | 2 | Reconocimiento activo o patrón de ataque identificado |
| Baja | 3 | Actividad sospechosa que requiere seguimiento |

---

## Reglas

### BERMA-001 — SSH Brute Force

**Protocolo / Puerto:** TCP / 22
**Severidad:** Alta (1)
**Classtype:** attempted-admin

**Justificación BERMA:**
La VPN corporativa sin MFA y TeamViewer con credenciales compartidas entre técnicos
hacen del puerto SSH un vector crítico de acceso no autorizado. Sin política de bloqueo
de cuentas ni límite de intentos fallidos, la fuerza bruta no encuentra ningún control
que la detenga. Detecta cinco intentos de conexión TCP SYN desde la misma IP en 60
segundos, umbral conservador para evitar falsos positivos por reconexiones legítimas.

```
alert tcp any any -> $HOME_NET 22 (
    msg:"BERMA-001 SSH Brute Force - Multiples intentos autenticacion";
    flags:S;
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:9000001;
    rev:1;
)
```

---

### BERMA-002 — Port Scan Horizontal

**Protocolo / Puerto:** TCP / Any
**Severidad:** Media (2)
**Classtype:** network-scan

**Justificación BERMA:**
La red IT/OT de BERMA está en el mismo segmento sin VLANs. El switch corporativo Cisco
SG350 conecta directamente con el switch industrial no gestionado, por lo que un escaneo
horizontal desde cualquier punto de la red expone PLCs S7-1500, HMI TP1200, servidores
Windows y endpoints en una sola pasada sin ninguna barrera. Detecta 20 SYN hacia puertos
distintos desde la misma IP en 5 segundos.

```
alert tcp any any -> $HOME_NET any (
    msg:"BERMA-002 Port Scan - Enumeracion red corporativa";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 5;
    classtype:network-scan;
    sid:9000002;
    rev:1;
)
```

---

### BERMA-003 — HMI Web Interface Access

**Protocolo / Puerto:** TCP / 80
**Severidad:** Media (2)
**Classtype:** web-application-attack

**Justificación BERMA:**
El HMI Siemens TP1200 tiene el acceso web habilitado con credenciales por defecto y está
conectado a la red corporativa sin segmentación. Cualquier petición HTTP al puerto 80
desde la red corporativa debe considerarse sospechosa hasta que exista segmentación de
red y cambio de credenciales. Umbral de 5 peticiones GET en 30 segundos para detectar
reconocimiento automatizado distinguiéndolo de accesos manuales puntuales.

```
alert tcp any any -> $HOME_NET 80 (
    msg:"BERMA-003 HMI Web Access - Acceso interfaz Siemens TP1200";
    flow:to_server,established;
    content:"GET";
    http_method;
    threshold:type both, track by_src, count 5, seconds 30;
    classtype:web-application-attack;
    sid:9000003;
    rev:1;
)
```

---

### BERMA-004 — Nikto Web Scanner

**Protocolo / Puerto:** TCP / 80
**Severidad:** Media (2)
**Classtype:** web-application-attack

**Justificación BERMA:**
WinCC V7.5 expone una interfaz web para monitorización SCADA que es accesible desde la
red corporativa sin autenticación fuerte. Nikto identifica directorios por defecto de
Siemens, métodos HTTP peligrosos habilitados, cabeceras de seguridad ausentes y
vulnerabilidades conocidas en la versión del servidor web industrial. Detecta el
User-Agent específico de Nikto en la cabecera HTTP.

```
alert tcp any any -> $HOME_NET 80 (
    msg:"BERMA-004 Web Scanner Nikto - Reconocimiento aplicacion web";
    flow:to_server,established;
    content:"Nikto";
    nocase;
    http_header;
    classtype:web-application-attack;
    sid:9000004;
    rev:1;
)
```

---

### BERMA-005 — Modbus TCP No Autorizado

**Protocolo / Puerto:** TCP / 502
**Severidad:** Alta (1)
**Classtype:** policy-violation

**Justificación BERMA:**
Los PLCs S7-1500 y el switch industrial están conectados directamente al switch
corporativo Cisco SG350 sin firewall intermedio. El puerto 502 (Modbus TCP) debe estar
activo únicamente en el segmento OT de control industrial. Cualquier tráfico Modbus
cruzando la red IT indica acceso directo no autorizado al segmento OT, con impacto
potencial sobre los 23 clientes en sectores agua, química y alimentaria.

```
alert tcp any any -> $HOME_NET 502 (
    msg:"BERMA-005 Modbus TCP - Acceso no autorizado segmento OT";
    flow:to_server,established;
    classtype:policy-violation;
    sid:9000005;
    rev:1;
)
```

---

### BERMA-006 — S7comm Siemens

**Protocolo / Puerto:** TCP / 102
**Severidad:** Alta (1)
**Classtype:** attempted-admin

**Justificación BERMA:**
TIA Portal V17 está instalado en 4 PCs sin control de versiones del código fuente. El
puerto 102 (ISO-TSAP/S7comm) debe estar activo únicamente entre las estaciones de
ingeniería autorizadas y los PLCs en la red OT. Nunca debe originarse desde IPs
externas, remotas o no identificadas. Un acceso no autorizado por este puerto permitiría
modificar la lógica de control de los PLCs en producción.

```
alert tcp any any -> $HOME_NET 102 (
    msg:"BERMA-006 S7comm Siemens - Intento acceso PLC no autorizado";
    flow:to_server,established;
    classtype:attempted-admin;
    sid:9000006;
    rev:1;
)
```

---

### BERMA-007 — Nmap Aggressive Scan

**Protocolo / Puerto:** TCP / Any
**Severidad:** Media (2)
**Classtype:** network-scan

**Justificación BERMA:**
La combinación de flags TCP SYN+FIN+PSH+URG es la firma característica del escaneo
agresivo de Nmap (-A). Esta combinación no aparece en tráfico legítimo bajo ninguna
circunstancia. Precede habitualmente a una fase de explotación dirigida contra los
servicios y versiones identificados durante el reconocimiento. En la red de BERMA
revelaría versiones de WinCC, firmware de PLCs y servicios expuestos en HMIs.

```
alert tcp any any -> $HOME_NET any (
    msg:"BERMA-007 Nmap Aggressive Scan - Reconocimiento avanzado detectado";
    flags:SFPU;
    classtype:network-scan;
    sid:9000007;
    rev:1;
)
```

---

### BERMA-008 — ICMP Echo Request Individual

**Protocolo / Puerto:** ICMP tipo 8
**Severidad:** Baja (3)
**Classtype:** network-scan

**Justificación BERMA:**
Cualquier ping hacia la red interna desde la red de atacantes o desde una IP no
identificada indica reconocimiento activo en curso. Esta regla dispara con cada echo
request individual para registrar el inicio exacto del reconocimiento en el log con
timestamp preciso, permitiendo correlacionar con otros eventos de la misma sesión.

```
alert icmp any any -> $HOME_NET any (
    msg:"BERMA-008 ICMP Echo Request - Reconocimiento activo red BERMA";
    itype:8;
    classtype:network-scan;
    sid:9000008;
    rev:1;
)
```

---

### BERMA-009 — ICMP Ping Sweep

**Protocolo / Puerto:** ICMP tipo 8
**Severidad:** Media (2)
**Classtype:** network-scan

**Justificación BERMA:**
Múltiples pings en poco tiempo indican enumeración automatizada de hosts activos en el
segmento IT/OT. Es el comportamiento característico de la fase de descubrimiento de
Nmap (-sn). En la red de BERMA un sweep exitoso revelaría PLCs, HMIs, servidores y
endpoints en el mismo segmento sin segmentar, proporcionando al atacante un mapa
completo de la infraestructura industrial. Umbral de 5 echo requests desde la misma
IP en 3 segundos.

```
alert icmp any any -> $HOME_NET any (
    msg:"BERMA-009 ICMP Ping Sweep - Enumeracion hosts segmento OT";
    itype:8;
    threshold:type both, track by_src, count 5, seconds 3;
    classtype:network-scan;
    sid:9000009;
    rev:1;
)
```

---

## Resumen de Reglas

| SID | Regla | Puerto | Severidad | Classtype |
|-----|-------|--------|-----------|-----------|
| 9000001 | BERMA-001 SSH Brute Force | TCP/22 | Alta | attempted-admin |
| 9000002 | BERMA-002 Port Scan | TCP/Any | Media | network-scan |
| 9000003 | BERMA-003 HMI Web Access | TCP/80 | Media | web-application-attack |
| 9000004 | BERMA-004 Nikto Scanner | TCP/80 | Media | web-application-attack |
| 9000005 | BERMA-005 Modbus TCP | TCP/502 | Alta | policy-violation |
| 9000006 | BERMA-006 S7comm Siemens | TCP/102 | Alta | attempted-admin |
| 9000007 | BERMA-007 Nmap Aggressive | TCP/Any | Media | network-scan |
| 9000008 | BERMA-008 ICMP Echo Request | ICMP/8 | Baja | network-scan |
| 9000009 | BERMA-009 ICMP Ping Sweep | ICMP/8 | Media | network-scan |

---

## Notas de Implementación

Las reglas se añaden en pfSense a través de Services > Snort > interfaz > Rules > Custom Rules.
Tras cualquier modificación es necesario reiniciar Snort en la interfaz afectada para
que las nuevas reglas entren en vigor.

Los SIDs del rango 9000000-9999999 están reservados para reglas locales y de laboratorio
según las directrices oficiales de Snort. No entran en conflicto con las reglas de
comunidad ni con las reglas de suscripción de Snort.

---

*BERMA Automatización e Ingeniería S.L. — Proyecto 3 Portfolio Ciberseguridad — Mayo 2026*
