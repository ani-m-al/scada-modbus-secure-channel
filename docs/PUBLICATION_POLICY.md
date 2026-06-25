# Publication Policy

La versión pública del repositorio conserva resultados derivados y scripts, pero retira datos que pueden revelar infraestructura o tráfico sensible.

## Datos Redactados

- Direcciones IP privadas.
- Direcciones MAC.
- IPv6 link-local.
- Rutas locales y nombres de usuario.
- Hostnames.
- SCI y valores MACsec derivados de identificadores de enlace.
- Asignaciones con nombres tipo `password`, `token`, `secret` o `api_key`.
- Payloads largos en hexadecimal.

## Datos Reemplazados por Placeholder

- Capturas crudas `.pcap` y `.pcapng`.
- Binarios y payloads crudos.
- Archivos comprimidos.
- Entornos virtuales locales.
- Artefactos compilados.
- Certificados o claves.

## Por Qué se Mantienen CSV y HTML

Los CSV y reportes HTML contienen métricas necesarias para reproducir el análisis de tesis sin exponer tráfico crudo. Cuando una columna contenía payload o valores hexadecimales de registros, se reemplazó por `REDACTED_PAYLOAD`.

## Trazabilidad

`SANITIZATION_MANIFEST.csv` contiene una fila por archivo original con:

- Ruta original redactada.
- Ruta pública resultante.
- Acción aplicada.
- Motivo.
- Tamaño del archivo original.

`SANITIZATION_SUMMARY.json` resume el volumen de archivos, acciones aplicadas y cantidad de identificadores detectados.

