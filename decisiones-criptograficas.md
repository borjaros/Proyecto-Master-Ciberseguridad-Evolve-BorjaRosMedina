# Decisiones Criptográficas — PKI Corporativa BERMA

## Contexto

BERMA Automatización e Ingeniería S.L. opera sistemas SCADA críticos con acceso remoto de técnicos de campo. Esta PKI proporciona la infraestructura de confianza que sustenta la autenticación de certificados, la VPN corporativa y la gestión de identidad digital.

---

## 1. ¿Por qué RSA 4096 para la CA Raíz?

### Decisión
La CA Raíz utiliza claves RSA de 4096 bits frente a los 2048 bits estándar.

### Justificación técnica
- La CA Raíz es el ancla de confianza de toda la infraestructura. Si su clave es comprometida, toda la PKI colapsa sin excepción.
- Una clave de 4096 bits ofrece aproximadamente 140 bits de seguridad equivalente, frente a los ~112 bits de RSA 2048. Esto proporciona un margen de seguridad amplio frente a avances computacionales futuros.
- La CA Raíz realiza muy pocas operaciones criptográficas (solo firmar CAs Intermedias), por lo que el coste computacional adicional de 4096 bits es irrelevante en la práctica.
- El certificado de la CA Raíz tiene una validez de 10 años. A mayor periodo de validez, mayor conveniencia de usar claves más largas.

### Criterio de elección
| Algoritmo | Seguridad equivalente | Uso recomendado |
|-----------|----------------------|-----------------|
| RSA 2048 | ~112 bits | Certificados finales, CAs Intermedias |
| RSA 4096 | ~140 bits | CA Raíz, activos de larga vida |
| ECDSA P-256 | ~128 bits | Entornos con restricciones de rendimiento |

> **Nota:** ECDSA P-256 ofrece seguridad equivalente a RSA 3072 con claves mucho más pequeñas y operaciones más rápidas. Para una PKI de nueva creación en producción, ECDSA sería la elección moderna. Se eligió RSA en este proyecto por compatibilidad con herramientas legacy presentes en el entorno OT de BERMA (PLCs Siemens S7-1500, HMI TP1200).

---

## 2. ¿Por qué una CA Intermedia?

### Decisión
La PKI implementa una jerarquía de dos niveles: CA Raíz → CA Intermedia → Certificados finales.

### Justificación técnica

**Aislamiento de riesgo:** La CA Raíz puede mantenerse completamente offline (airgapped), sacándola únicamente para firmar nuevas CAs Intermedias. Si la CA Intermedia es comprometida, se puede revocar y emitir una nueva sin tocar la CA Raíz. Si la CA Raíz fuera la única y fuera comprometida, habría que reemplazar absolutamente todos los certificados de la infraestructura.

**Separación de responsabilidades:** En entornos enterprise, diferentes CAs Intermedias pueden gestionar diferentes dominios de confianza (usuarios, servidores, dispositivos OT) con políticas distintas.

**`pathlen:0` en la CA Intermedia:** Esta extensión impide que la CA Intermedia pueda crear sub-CAs por debajo de ella. Esto limita el radio de daño en caso de compromiso: aunque alguien obtuviera la clave de la intermedia, no podría crear una CA adicional que los clientes confiaran automáticamente.

```
BERMA Root CA (offline, airgapped)
└── BERMA Intermediate CA (online, pathlen:0)
    ├── Certificados de servidor
    ├── Certificados de cliente/técnico
    └── [No puede crear más CAs]
```

### Por qué NO usar una CA de un solo nivel
- La CA Raíz tendría que estar online para firmar certificados finales → mayor superficie de ataque.
- No hay posibilidad de revocación parcial: comprometer la raíz = comprometer todo.
- No es escalable: no se pueden delegar dominios de gestión a equipos diferentes.

---

## 3. ¿Por qué SHA-256?

### Decisión
Todos los certificados utilizan SHA-256 como algoritmo de hash para la firma digital.

### Justificación técnica
- **SHA-1 está roto:** En 2017, Google demostró el primer ataque de colisión práctico contra SHA-1 (SHAttered). Desde entonces, los principales navegadores y sistemas operativos rechazan certificados firmados con SHA-1.
- **SHA-256 es el estándar actual:** Ofrece 128 bits de seguridad en resistencia a colisiones, considerado suficiente para el horizonte temporal actual.
- **SHA-384/SHA-512** ofrecen mayor seguridad pero no aportan ventajas prácticas para una PKI interna de estas características.

---

## 4. ¿Por qué RSA 2048 para la CA Intermedia y certificados finales?

### Decisión
La CA Intermedia y los certificados de servidor/cliente usan RSA 2048 bits.

### Justificación técnica
- RSA 2048 proporciona ~112 bits de seguridad equivalente, considerado suficiente según NIST hasta al menos 2030.
- Los certificados finales tienen validez de 375 días (1 año + margen). En ese periodo, RSA 2048 es completamente seguro.
- La CA Intermedia realiza operaciones frecuentes (firmar certificados), donde el rendimiento sí importa frente a la CA Raíz.
- Compatibilidad total con los dispositivos OT del entorno BERMA.

---

## 5. ¿Por qué 375 días de validez en certificados finales?

### Decisión
Los certificados de servidor y cliente tienen una validez de 375 días en lugar del año natural (365 días).

### Justificación técnica
- Los navegadores y sistemas modernos rechazan certificados con validez superior a 398 días (decisión adoptada por Apple, Google y Mozilla desde 2020).
- 375 días proporciona un margen de 10 días sobre el año natural para gestionar la renovación sin urgencia.
- Periodos cortos de validez limitan la ventana de exposición si un certificado es comprometido sin que se detecte.

---

## 6. ¿Por qué proteger la clave privada de la CA Raíz con AES-256?

### Decisión
La clave privada de la CA Raíz se cifra en disco con AES-256 mediante passphrase (flag `-aes256` en OpenSSL).

### Justificación técnica
- Si el archivo `ca.key` es robado (acceso físico al sistema, backup mal protegido, etc.), el atacante no puede usarlo sin la passphrase.
- AES-256 con una passphrase fuerte es computacionalmente infactible de romper con la tecnología actual.
- Las claves de servidor (sin passphrase) se justifican porque los servicios necesitan arrancar automáticamente sin intervención humana. La CA Raíz no tiene ese requisito.

### Regla general
| Tipo de clave | Passphrase | Razón |
|---------------|-----------|-------|
| CA Raíz | ✅ Obligatoria | Máxima protección, uso manual |
| CA Intermedia | ✅ Obligatoria | Alta protección, uso infrecuente |
| Servidor/cliente | ❌ Opcional | Necesita arranque automático |

---

## 7. Extensiones X.509 críticas implementadas

### `basicConstraints = critical, CA:true`
Indica que el certificado pertenece a una CA y puede firmar otros certificados. La marca `critical` significa que cualquier sistema que no entienda esta extensión debe rechazar el certificado.

### `keyUsage = critical, keyCertSign, cRLSign`
Restringe el uso de la clave a firma de certificados y firma de CRLs. Impide que la clave de la CA se use para otros propósitos (cifrado de datos, autenticación de cliente, etc.).

### `extendedKeyUsage = serverAuth / clientAuth`
Restringe los certificados finales a su propósito específico. Un certificado de servidor no puede usarse como certificado de cliente y viceversa.

### `crlDistributionPoints`
Indica a los clientes dónde descargar la CRL para verificar si el certificado ha sido revocado. Sin este campo, los clientes no sabrían dónde comprobar el estado de revocación.
