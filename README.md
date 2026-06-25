# SCADA Modbus Secure Channel

Repositorio de herramientas, evidencias y resultados para evaluar el impacto de un canal seguro en comunicaciones SCADA/Modbus TCP. El objetivo es comparar escenarios sin canal seguro, puente transparente y MACsec usando métricas de red, recursos del host, comportamiento Modbus y entropía de tráfico.

Este repositorio acompaña un trabajo de tesis. Contiene resultados públicos reproducibles y scripts de análisis; no contiene capturas crudas ni identificadores reales de la infraestructura.

## Contenido

| Ruta | Descripción |
| --- | --- |
| `scripts/` | Herramientas de medición, caracterización Modbus, entropía y gráficas de RAM. |
| `Baseline/` | Corridas del escenario base sin canal seguro. Incluye mediciones cortas y de 1 hora. |
| `Bridge/` | Corridas del escenario puente/transparente. Incluye mediciones de red, rendimiento y perfil Modbus. |
| `MACSec/` | Corridas del escenario con MACsec, análisis de entropía y caracterización Modbus. |
| `ram_figures_all_runs/` | Figuras comparativas de memoria generadas desde `vmstat`/`pidstat`. |
| `docs/` | Guía de metodología, estructura de datos, uso de scripts y notas de publicación. |
| `SANITIZATION_MANIFEST.csv` | Inventario público de archivos originales y acción aplicada al publicar. |
| `SANITIZATION_SUMMARY.json` | Resumen cuantitativo de la exportación pública. |

## Pregunta Experimental

La evaluación busca responder cuánto cambia el desempeño y la observabilidad de una comunicación SCADA/Modbus TCP cuando se introduce un canal seguro a nivel de enlace, manteniendo comparable la carga de aplicación.

Las dimensiones medidas son:

- Latencia ICMP y latencia de conexión TCP al puerto Modbus.
- Estabilidad TCP, conteos de paquetes y tasas de tráfico por interfaz.
- Uso de CPU, RAM, swap y procesos dominantes durante la corrida.
- Perfil Modbus: funciones, endpoints, transacciones, RTT, registros consultados y ciclos de sondeo.
- Entropía de payload o tramas protegidas como evidencia complementaria de confidencialidad.

## Escenarios

| Escenario | Propósito |
| --- | --- |
| `Baseline` | Referencia sin canal seguro. Permite establecer latencia y consumo base. |
| `Bridge` | Tránsito por puente/intermediario sin cifrado MACsec. Sirve para aislar sobrecosto de encaminamiento o bridging. |
| `MACSec` | Canal protegido con MACsec. Permite comparar sobrecosto y cambio de entropía frente a baseline/bridge. |

## Uso Rápido

Instalar dependencias recomendadas en Ubuntu/WSL:

```bash
sudo apt update
sudo apt install -y iputils-ping iproute2 sysstat iperf3 tshark tcpdump mtr-tiny nmap openssl procps python3 python3-venv ethtool binutils
python3 -m venv .venv_modbus
source .venv_modbus/bin/activate
pip install --upgrade pip
pip install scapy pandas matplotlib
```

Ejecutar una corrida de medición SCADA/Modbus:

```bash
sudo ./scripts/scada_probe_v1_1_multiiface.sh \
  --label macsec_1h \
  --target <TARGET_IP> \
  --port 502 \
  --ifaces <IFACE_1>,<IFACE_2>,macsec0 \
  --duration 3600 \
  --out ./results
```

Caracterizar Modbus desde una captura:

```bash
python3 ./scripts/modbus_characterizer_v4.py \
  --pcap ./capture.pcapng \
  --window-sec 5 \
  --out ./results/modbus_profile
```

Calcular entropía de una captura:

```bash
python3 ./scripts/entropy_calc.py ./capture.pcapng --mode all
```

Regenerar gráficas de RAM desde corridas existentes:

```bash
python3 ./scripts/graficar_ram_vmstat.py \
  --root . \
  --mem-total-mib 24032 \
  --top-n 12
```

La guía completa de scripts está en [`docs/SCRIPTS.md`](docs/SCRIPTS.md).

## Cómo Leer los Resultados

Cada corrida del probe contiene, cuando aplica:

- `probe_report.html`: reporte interpretado de la corrida.
- `csv/key_metrics_compact.csv`: métricas principales para comparación rápida.
- `csv/latency_stats.csv` y `csv/latency_samples.csv`: latencia agregada y muestras.
- `csv/network_rates.csv` e `interface_delta.csv`: uso de interfaces.
- `csv/cpu_process_summary.csv`: procesos con mayor consumo de CPU.
- `raw/`: logs crudos saneados de herramientas del sistema.

Cada perfil Modbus contiene:

- `modbus_profile_report.html`: reporte HTML del comportamiento Modbus.
- `csv/modbus_transactions.csv`: transacciones request/response y RTT.
- `csv/modbus_adus.csv`: ADUs Modbus observados.
- `csv/function_summary.csv`: distribución por código de función.
- `csv/endpoint_summary.csv`: pares cliente/servidor.
- `csv/polling_summary.csv`: ciclos de consulta.

La estructura completa está documentada en [`docs/DATASET.md`](docs/DATASET.md) y la metodología en [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

## Nota de Publicación

Esta es una versión pública. Los identificadores reales de red, host y usuario fueron reemplazados por marcadores como `PRIVATE_IP_###` y `MAC_ADDR_###`. Las capturas crudas (`.pcap`, `.pcapng`), binarios, payloads y archivos comprimidos se sustituyeron por placeholders para evitar exposición de tráfico o datos sensibles.

La sanitización no es el objetivo del repositorio; es una medida para publicar evidencia experimental sin revelar detalles de la infraestructura. El inventario está en `SANITIZATION_MANIFEST.csv`.

