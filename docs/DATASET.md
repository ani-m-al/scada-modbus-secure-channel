# Dataset Layout

Este repositorio conserva la forma del árbol original, pero con identificadores saneados.

## Directorios de Escenario

### `Baseline/`

Contiene corridas de referencia. Las subcarpetas incluyen mediciones cortas, análisis Modbus y una corrida de 1 hora en `Rendimiento_1h`.

Uso típico:

- Establecer métricas base de latencia y recursos.
- Comparar el perfil Modbus sin canal seguro.
- Revisar estabilidad en una corrida prolongada.

### `Bridge/`

Contiene resultados del escenario puente/transparente.

Uso típico:

- Aislar el costo de atravesar el puente.
- Comparar tasas de interfaz frente a baseline.
- Revisar si el patrón Modbus se mantiene estable.

### `MACSec/`

Contiene resultados del escenario protegido.

Uso típico:

- Evaluar sobrecosto de MACsec.
- Comparar entropía frente a baseline/bridge.
- Revisar recursos consumidos por la protección de enlace.

## Estructura de una Corrida del Probe

Una corrida generada por `scada_probe` suele tener:

```text
README.txt
metadata.txt
notes.txt
commands.log
probe_report.html
csv/
raw/
figures/
pcap/
```

Archivos clave:

- `metadata.txt`: parámetros de corrida.
- `commands.log`: comandos ejecutados para generar evidencia.
- `probe_report.html`: resumen interpretado.
- `csv/summary.csv`: métricas agregadas.
- `csv/probe_dataset.csv`: tabla normalizada con muestras y métricas.
- `csv/key_metrics_compact.csv`: selección de métricas para comparación.
- `raw/`: salidas saneadas de herramientas del sistema.
- `pcap/`: placeholders públicos cuando la captura cruda fue retirada.

## Estructura de un Perfil Modbus

Un perfil generado por `modbus_characterizer_v4.py` suele tener:

```text
modbus_profile_report.html
csv/modbus_adus.csv
csv/modbus_transactions.csv
csv/function_summary.csv
csv/endpoint_summary.csv
csv/register_activity.csv
csv/polling_summary.csv
csv/tcp_stability.csv
csv/run_metadata.csv
```

Interpretación:

- `modbus_adus.csv`: unidades de datos Modbus observadas.
- `modbus_transactions.csv`: asociación request/response y RTT.
- `function_summary.csv`: distribución por función Modbus.
- `endpoint_summary.csv`: pares cliente-servidor.
- `register_activity.csv`: registros consultados.
- `polling_summary.csv`: periodicidad de consultas.
- `tcp_stability.csv`: indicadores de estabilidad TCP.

## Figuras

Las figuras públicas conservan las curvas, pero su título fue reemplazado para no exponer identificadores del entorno. Las rutas de archivo también usan marcadores como `PRIVATE_IP_###`.

## Placeholders

Los archivos con sufijo `.REDACTED.txt` sustituyen artefactos que no deben publicarse crudos:

- Capturas `.pcap`/`.pcapng`.
- Payloads TCP o dumps binarios.
- Archivos comprimidos.
- Certificados, claves o artefactos compilados.

Cada placeholder indica la razón de sustitución y el tamaño del archivo original.

