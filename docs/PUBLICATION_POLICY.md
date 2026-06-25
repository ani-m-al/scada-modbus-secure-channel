# Publication Policy

La versión pública del repositorio conserva metodología, scripts, métricas agregadas, reportes y resultados derivados. No publica datos que puedan revelar infraestructura sensible, tráfico operacional crudo o material criptográfico.

## Datos Redactados

- Direcciones IP privadas reales.
- Direcciones MAC.
- IPv6 link-local.
- Rutas locales y nombres de usuario.
- Hostnames.
- SCI y valores MACsec derivados de identificadores de enlace.
- Asignaciones con nombres tipo `password`, `token`, `secret` o `api_key`.
- Payloads largos en hexadecimal.
- Comandos históricos que contengan claves o secretos.

## Datos Reemplazados por Placeholder

- Capturas crudas `.pcap` y `.pcapng`.
- Binarios y payloads crudos.
- Archivos comprimidos.
- Entornos virtuales locales.
- Artefactos compilados.
- Certificados o claves.
- Archivos de configuración con credenciales.

## Material que No Debe Publicarse

- Claves CAK.
- Claves SAK.
- CKN real si identifica el entorno.
- Certificados privados.
- Claves precompartidas.
- Configuraciones con secretos.
- Capturas con credenciales o direcciones sensibles no anonimizadas.
- Instrucciones que permitan reproducir acceso no autorizado fuera del laboratorio.

## Material Publicable

- Scripts propios sin secretos.
- Métricas agregadas.
- CSV con identificadores anonimizados.
- Reportes HTML saneados.
- Figuras sin títulos o rutas sensibles.
- Parámetros técnicos no secretos, por ejemplo `macsec0`, EtherType `0x88E5`, puerto Modbus `502`, modo de evaluación y criterios de aceptación.

## Por Qué se Mantienen CSV y HTML

Los CSV y reportes HTML contienen métricas necesarias para reproducir el análisis de tesis sin exponer tráfico crudo. Cuando una columna contenía payload o valores hexadecimales de registros, se reemplazó por `REDACTED_PAYLOAD`.

## Trazabilidad

`SANITIZATION_MANIFEST.csv` contiene una fila por archivo original con:

- ruta original redactada;
- ruta pública resultante;
- acción aplicada;
- motivo;
- tamaño del archivo original.

`SANITIZATION_SUMMARY.json` resume el volumen de archivos, acciones aplicadas y cantidad de identificadores detectados.

## Nota sobre Pruebas de Ataque

Las pruebas de sniffing, manipulación, repetición o intermediación deben documentarse únicamente como validación controlada en un entorno propio o autorizado. El repositorio público debe describir el criterio de evaluación y resultados, no material operativo reutilizable para afectar terceros.

