# Decisiones de Seguridad — Proyecto 1
## Infraestructura Web Segura y Monitorizada
**Empresa:** BERMA Automatización e Ingeniería S.L.  
**Servidor:** srv01.berma.local  
**Fecha:** 2024

---

## 1. Nginx como reverse proxy en vez de Apache2 directamente expuesto

Apache2 queda configurado en `127.0.0.1:8080` y nunca recibe conexiones directas del exterior. Nginx es el único servicio expuesto en los puertos 80 y 443, y gestiona SSL termination, HSTS y cabeceras de seguridad en un único punto de entrada.

**Por qué es más seguro que la configuración por defecto:**  
Si Apache2 tuviera una vulnerabilidad explotable remotamente, no sería accesible desde fuera de la máquina porque solo escucha en localhost. En la configuración por defecto Apache2 escucha en `0.0.0.0:80`, expuesto directamente a la red.

**En una auditoría se valoraría:**  
Separación de responsabilidades entre el servidor que gestiona TLS y el que sirve contenido. Reducción de superficie de ataque.

---

## 2. Certificado x509 propio con OpenSSL en vez de Let's Encrypt

Se ha creado una CA propia (`BERMA-ROOT-CA`) con clave RSA 4096 bits, válida 10 años. El certificado del servidor ha sido generado con clave RSA 2048 bits, firmado por la CA con extensiones SAN para `web.berma.local`, `srv01.berma.local` y la IP `10.10.10.50`.

**Por qué no se usa Let's Encrypt:**  
Let's Encrypt requiere validación pública del dominio mediante HTTP-01 o DNS-01 challenge. El dominio `berma.local` es interno y no tiene resolución pública en internet, por lo que Let's Encrypt no puede validarlo. Una PKI interna es la solución correcta para redes corporativas con dominios internos.

**Por qué es mejor que un certificado autofirmado simple:**  
La arquitectura CA raíz → certificado servidor replica exactamente cómo funcionan las CAs comerciales. En un entorno real, el `ca.crt` se distribuiría a todos los equipos del dominio mediante GPO de Active Directory de BERMA, eliminando el aviso de certificado no confiable en todos los navegadores corporativos.

**Campos del CSR y su significado:**

| Campo | Valor | Significado |
|-------|-------|-------------|
| C | ES | Country — código ISO del país |
| ST | Madrid | State — comunidad autónoma |
| L | Getafe | Locality — ciudad |
| O | BERMA Automatizacion e Ingenieria SL | Organization — nombre legal |
| OU | IT | Organizational Unit — departamento |
| CN | web.berma.local | Common Name — nombre del servicio |

**Qué fallaría en una auditoría sin esto:**  
Sin SAN el certificado sería rechazado por navegadores modernos aunque el CN fuera correcto. Chrome y Firefox ignoraron el CN en favor de SAN desde 2017.

---

## 3. HSTS — Strict-Transport-Security

Configurado en Nginx con `max-age=31536000; includeSubDomains` (1 año).

**Por qué es necesario:**  
Sin HSTS, aunque exista redirección de HTTP a HTTPS, un atacante en la misma red puede interceptar la petición HTTP inicial antes de que se produzca la redirección (SSL stripping attack). Con HSTS el navegador rechaza directamente cualquier conexión HTTP a ese dominio sin consultarlo al servidor, durante el tiempo definido en `max-age`.

**Qué fallaría en una auditoría sin esto:**  
Un test con SSLLabs o similar detectaría la ausencia de HSTS como finding de severidad media. En entornos con datos sensibles se consideraría finding alto.

---

## 4. Puerto 2222 para SSH en vez del puerto 22 por defecto

**Por qué se cambia el puerto:**  
Cambiar el puerto no es seguridad real por oscuridad, pero elimina el ruido de bots automatizados que escanean el puerto 22 de forma masiva y continua. Los logs de `auth.log` quedan significativamente más limpios y fail2ban trabaja con menos eventos irrelevantes.

**En una auditoría se documentaría como:**  
Medida de reducción de superficie de ataque y reducción de ruido en logs, no como control de seguridad primario. El control primario es la autenticación por clave pública.

---

## 5. ED25519 para claves SSH en vez de RSA-2048

**Por qué ED25519:**  
ED25519 usa criptografía de curva elíptica (Curve25519). Con 256 bits ofrece una seguridad equivalente a RSA-3000 bits. Es más rápido en operaciones de firma y verificación, genera claves más cortas y no tiene los problemas de implementación que afectan históricamente a DSA.

**Recomendación de organismos:**  
NIST y BSI recomiendan ED25519 para nuevas implementaciones desde 2020. RSA-2048 sigue siendo seguro pero ED25519 es la opción moderna preferida para SSH.

---

## 6. Deshabilitar root login en SSH

`PermitRootLogin no` en la configuración de SSH.

**Por qué es necesario:**  
Si root puede autenticarse por SSH y un atacante comprometiera las credenciales o la clave privada, tendría acceso total al sistema de forma inmediata sin necesidad de escalar privilegios. Con root deshabilitado, cualquier acceso requiere comprometer primero una cuenta de usuario sin privilegios y luego usar `sudo`, añadiendo una capa de defensa en profundidad.

**Qué fallaría en una auditoría sin esto:**  
Cualquier auditoría de hardening Linux detectaría `PermitRootLogin yes` como finding crítico.

---

## 7. fail2ban con jail SSH

Configurado con `bantime=3600` (1 hora), `maxretry=3` intentos en `findtime=600` segundos (10 minutos). La red local `10.10.10.0/24` está en `ignoreip` para evitar autobloqueos.

**Por qué estos valores:**  
3 intentos fallidos es suficiente para detectar un ataque de fuerza bruta automatizado sin generar falsos positivos por errores humanos normales (dos intentos fallidos es habitual). Un baneo de 1 hora ralentiza significativamente cualquier ataque distribuido.

---

## 8. Cabeceras de seguridad adicionales en Nginx

- `X-Frame-Options: SAMEORIGIN` — previene ataques de clickjacking embebiendo la web en un iframe externo.
- `X-Content-Type-Options: nosniff` — impide que el navegador intente adivinar el tipo MIME de la respuesta, previniendo ataques de MIME sniffing.
- `server_tokens off` — oculta la versión de Nginx en las cabeceras de respuesta, reduciendo la información disponible para un atacante en fase de reconocimiento.

---

## 9. Qué fallaría en una auditoría completa de este sistema

| Finding | Severidad | Solución en producción |
|---------|-----------|----------------------|
| CA no distribuida a equipos cliente | Media | Distribuir `ca.crt` por GPO de Active Directory |
| Zabbix frontend sin HTTPS | Media | Añadir SSL al virtualhost de Zabbix en Nginx |
| Servidor único sin redundancia | Alta | Añadir servidor secundario con replicación |
| Sin segmentación de red IT/OT | Alta | Implementar VLANs separadas (ver Proyecto 2) |
| Certificado de servidor válido solo 365 días | Baja | Automatizar renovación con script o ACME interno |
| Sin rotación automática de logs | Baja | Configurar logrotate para auth.log y nginx logs |
