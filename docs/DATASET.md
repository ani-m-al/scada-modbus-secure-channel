# Dataset Layout

Este repositorio conserva la forma del árbol original para mantener trazabilidad con las corridas ejecutadas. Los identificadores sensibles fueron reemplazados por marcadores públicos.

Para nuevos experimentos, usar la convención documentada en [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

## Mapa Lógico

| Escenario canónico | Carpeta pública actual | Descripción |
| --- | --- | --- |
| `baseline` | `Baseline/` | Comunicación original sin puente ni canal seguro adicional. |
| `bridge` | `Bridge/` | Comunicación con puente transparente sin cifrado. |
| `macsec` | `MACSec/` | Comunicación protegida mediante MACsec. |

## `Baseline/`

Contiene corridas de referencia. Las subcarpetas incluyen mediciones cortas, análisis Modbus y una corrida extendida en `Rendimiento_1h`.

Uso típico:

- establecer métricas base de latencia y recursos;
- comparar el perfil Modbus sin canal seguro;
- revisar estabilidad en una ventana prolongada;
- estimar umbrales relativos para evaluar `bridge` y `macsec`.

## `Bridge/`

Contiene resultados del escenario puente/transparente.

Uso típico:

- aislar el costo de atravesar el puente;
- comparar tasas de interfaz frente a línea base;
- revisar si el patrón Modbus se mantiene estable;
- separar el sobrecosto del equipo intermedio del sobrecosto criptográfico.

## `MACSec/`

Contiene resultados del escenario protegido.

Uso típico:

- evaluar sobrecosto de MACsec;
- comparar entropía frente a `baseline` y `bridge`;
- revisar recursos consumidos por la protección de enlace;
- verificar que el tráfico observado en el enlace protegido no sea decodificable como Modbus útil.

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
- `csv/key_metrics_compact.csv`: selección de métricas para comparación rápida.
- `csv/latency_stats.csv`: latencia agregada.
- `csv/tcp_connect_stats.csv`: latencia de conexión TCP al puerto Modbus.
- `csv/cpu_process_summary.csv`: consumo de CPU por proceso.
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
- `endpoint_summary.csv`: pares cliente-servidor anonimizados.
- `register_activity.csv`: registros consultados, con payload sensible redactado cuando aplica.
- `polling_summary.csv`: periodicidad de consultas.
- `tcp_stability.csv`: indicadores de estabilidad TCP.

## Figuras

Las figuras públicas conservan las curvas y tendencias, pero los títulos o rutas fueron sustituidos cuando podían exponer identificadores del entorno. Las rutas de archivo usan marcadores como `PRIVATE_IP_###`.

## Placeholders

Los archivos con sufijo `.REDACTED.txt` sustituyen artefactos que no deben publicarse crudos:

- capturas `.pcap`/`.pcapng`;
- payloads TCP o dumps binarios;
- archivos comprimidos;
- certificados, claves o artefactos compilados.

Cada placeholder indica la razón de sustitución y el tamaño del archivo original.

