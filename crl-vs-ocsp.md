# CRL vs OCSP — Mecanismos de Revocación de Certificados

## ¿Qué es la revocación?

Un certificado X.509 tiene una fecha de expiración, pero puede necesitar invalidarse antes de ese momento por múltiples razones: compromiso de la clave privada, cambio de rol del empleado, desmantelamiento de un servicio, o errores en la emisión. Los mecanismos de revocación permiten a los clientes verificar si un certificado sigue siendo válido antes de confiar en él.

---

## CRL — Certificate Revocation List

### Funcionamiento
La CA publica periódicamente un archivo firmado que contiene la lista de números de serie de todos los certificados revocados. Los clientes descargan este archivo y comprueban localmente si el certificado que están evaluando aparece en la lista.

```
Cliente → Descarga CRL desde URL pública → Comprueba número de serie localmente
```

### Implementación en BERMA
```
CRL publicada en: http://192.168.100.10/crl/intermediate.crl
Frecuencia de actualización: cada 30 días (o inmediata tras revocación)
Distribución: Apache2 sirviendo el archivo estáticamente
```

### Ventajas
- **Simplicidad:** No requiere infraestructura adicional. Un servidor HTTP es suficiente.
- **Privacidad:** El cliente descarga la lista completa y comprueba localmente. La CA no sabe qué certificados está verificando el cliente.
- **Sin dependencia online en tiempo real:** Una vez descargada la CRL, las verificaciones son locales.
- **Compatibilidad universal:** Todos los sistemas con soporte X.509 entienden CRLs.

### Desventajas
- **Latencia de revocación:** Si la CRL se publica cada 24 horas, un certificado revocado puede seguir siendo aceptado hasta la próxima publicación.
- **Tamaño creciente:** En PKIs con muchos certificados, la CRL puede crecer significativamente.
- **Descarga completa:** El cliente descarga toda la lista aunque solo necesite verificar un certificado.

---

## OCSP — Online Certificate Status Protocol

### Funcionamiento
En lugar de descargar una lista completa, el cliente envía una consulta en tiempo real a un servidor OCSP Responder preguntando por el estado de un certificado específico. El servidor responde con `good`, `revoked` o `unknown`.

```
Cliente → Consulta OCSP Responder con número de serie → Respuesta: good/revoked/unknown
```

### Ventajas
- **Respuesta en tiempo real:** La revocación es efectiva inmediatamente.
- **Eficiencia:** El cliente solo pregunta por el certificado que necesita, no descarga miles de entradas.
- **Información actualizada:** No hay ventana de gracia entre la revocación y la detección.

### Desventajas
- **Privacidad comprometida:** La CA sabe exactamente qué certificados verifica cada cliente, cuándo y desde qué IP. Esto es especialmente sensible en PKIs públicas.
- **Infraestructura adicional:** Requiere un OCSP Responder disponible 24/7. Si cae, los clientes pueden rechazar todos los certificados o ignorar la verificación.
- **Latencia en cada conexión:** Cada handshake TLS incluye una consulta de red adicional.
- **Complejidad:** Implementación y mantenimiento significativamente más complejos que una CRL.

---

## Comparativa directa

| Criterio | CRL | OCSP |
|----------|-----|------|
| Mecanismo | Lista descargada por el cliente | Consulta en tiempo real |
| Latencia de revocación | Hasta el próximo ciclo de publicación | Inmediata |
| Privacidad del cliente | Alta (verificación local) | Baja (CA registra consultas) |
| Disponibilidad requerida | Baja (archivo estático) | Alta (servicio 24/7) |
| Complejidad de implementación | Baja | Alta |
| Escalabilidad | Limitada (CRL crece) | Alta |
| Compatibilidad | Universal | Amplia (no universal en OT) |
| Dependencia de red en tiempo real | No | Sí |
| **Elección para BERMA** | ✅ Implementada | Para producción a escala |

### OCSP Stapling
Existe una variante llamada OCSP Stapling que mitiga el problema de privacidad: el servidor obtiene periódicamente su propia respuesta OCSP y la adjunta al handshake TLS. El cliente recibe la respuesta sin consultar directamente a la CA. Es el estándar moderno en servidores web públicos con HTTPS.

---

## ¿Cuándo usar PKI propia vs Let's Encrypt vs CA Comercial?

Esta es la pregunta de arquitectura más importante al diseñar una infraestructura de certificados. La respuesta depende del contexto, no hay una solución universalmente correcta.

### PKI Propia (este proyecto)

**Úsala cuando:**
- Los servicios son internos y no accesibles desde internet (intranet, VPN, OT/SCADA).
- Necesitas autenticación mutua TLS (mTLS) entre servicios o dispositivos.
- Los dispositivos clientes no tienen acceso a internet para validar certificados de CAs públicas.
- Necesitas control total sobre el ciclo de vida de los certificados (emisión, renovación, revocación).
- El entorno tiene dispositivos legacy que no confían en CAs públicas modernas.
- Tienes requisitos de privacidad que impiden usar CAs externas (sector defensa, infraestructura crítica).

**Ejemplos reales:**
- Autenticación de técnicos de campo en sistemas SCADA (caso BERMA).
- Comunicaciones entre microservicios en una red privada.
- VPN corporativa con autenticación por certificado.
- Dispositivos IoT industriales con comunicación M2M.

**Coste:** Alto en implementación inicial, bajo en operación continua.

---

### Let's Encrypt

**Úsala cuando:**
- El servicio es público y accesible desde internet (web pública, API pública).
- Necesitas HTTPS en un dominio público de forma gratuita y automatizada.
- No necesitas certificados de cliente ni mTLS.
- Quieres renovación automática sin gestión manual (protocolo ACME).

**Limitaciones:**
- Solo emite certificados de servidor (DV — Domain Validation). No emite certificados de cliente.
- Requiere que el dominio sea público y accesible desde internet para la validación.
- No funciona para IPs privadas ni dominios internos (`.local`, `.internal`).
- Validez de 90 días (diseñado para renovación automática).

**Ejemplos reales:**
- Web corporativa pública con HTTPS.
- API REST accesible desde internet.
- Cualquier servicio con nombre de dominio público.

**Coste:** Gratuito.

---

### CA Comercial (DigiCert, Sectigo, GlobalSign)

**Úsala cuando:**
- Necesitas certificados EV (Extended Validation) para transmitir máxima confianza visual (banca online, e-commerce de alto valor).
- Necesitas certificados Wildcard o Multi-SAN para múltiples subdominios.
- El contexto legal o regulatorio exige una CA auditada externamente (PCI-DSS, eIDAS).
- Necesitas soporte técnico con SLA garantizado.
- Los certificados deben ser confiados automáticamente por cualquier dispositivo del mundo sin configuración adicional.

**Limitaciones:**
- Coste elevado (desde decenas hasta miles de euros por certificado/año).
- Dependencia de un tercero externo.
- No emiten certificados para IPs privadas ni servicios internos.

**Ejemplos reales:**
- Plataforma de pagos online que necesita el candado verde EV.
- Empresa con obligaciones de cumplimiento normativo (PCI-DSS, eIDAS).
- Multinacional que necesita certificados reconocidos en todos los países.

---

## Árbol de decisión

```
¿El servicio es accesible públicamente desde internet?
├── SÍ → ¿Necesitas EV o cumplimiento normativo estricto?
│         ├── SÍ → CA Comercial
│         └── NO → Let's Encrypt
└── NO → ¿Es un servicio interno, VPN o entorno OT/SCADA?
          └── SÍ → PKI Propia
```

---

## Decisión para BERMA

BERMA opera servicios de acceso remoto a sistemas SCADA industriales en una red privada, con técnicos de campo que necesitan autenticación por certificado. Ninguna CA pública puede emitir certificados para IPs privadas ni para autenticación mutua de clientes en este contexto. La PKI propia es la única opción técnicamente correcta para este escenario.
