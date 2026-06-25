# SCADA Modbus Secure Channel

Repositorio público del proyecto técnico:

**Diseño e Implementación de un Canal Seguro Transparente para la Comunicación SCADA-API en el Laboratorio de Micro-Red de la Universidad de Cuenca**

Autores:

- Aníbal Martín Macas Villagómez
- Anthony Josué Pallchisaca Valverde

Área: **Redes de Telecomunicaciones**.

Este repositorio contiene scripts, resultados experimentales sanitizados y documentación metodológica para evaluar un canal seguro transparente en comunicaciones SCADA/Modbus TCP. La publicación conserva métricas, reportes y evidencias derivadas, pero retira identificadores reales de infraestructura, capturas crudas, claves y artefactos sensibles.

## Objetivo

Implementar un mecanismo de cifrado y autenticación transparente en el canal de comunicación entre el controlador de estación/API y el servidor SCADA de la Micro-Red de la Universidad de Cuenca, con el fin de garantizar la confidencialidad e integridad de la telemetría operativa frente a amenazas internas, validando su impacto sobre el rendimiento y la disponibilidad del sistema.

## Pregunta de Investigación

¿Qué mecanismo de cifrado y autenticación resulta más efectivo para asegurar el enlace entre la API/PLC y el servidor SCADA, garantizando la confidencialidad e integridad de la telemetría sin degradar el rendimiento operativo del sistema?

## Hipótesis

La implementación de un canal seguro transparente entre el servidor SCADA y la API/PLC reduce la exposición del tráfico Modbus TCP frente a sniffing, manipulación y repetición, sin afectar de forma significativa la latencia, la disponibilidad ni la continuidad operativa del sistema.

Operativamente, se espera que el canal seguro:

- reduzca la decodificabilidad del tráfico Modbus observable en el enlace protegido;
- incremente la entropía de la región protegida hasta valores compatibles con tráfico cifrado;
- impida modificaciones transparentes por un intermediario no autorizado;
- mantenga el ciclo de sondeo Modbus y la tasa de transacciones funcionales dentro de márgenes aceptables;
- introduzca una sobrecarga baja de CPU/RAM en el puente o extremo de seguridad.

## Escenarios Evaluados

| Nombre canónico | Carpeta pública | Propósito |
| --- | --- | --- |
| `baseline` | `Baseline/` | Comunicación SCADA-API/PLC sin canal seguro adicional. Establece referencia de latencia, estabilidad, ciclo Modbus y exposición del contenido. |
| `bridge` | `Bridge/` | Comunicación atravesando un puente transparente sin cifrado. Permite aislar el impacto operativo del equipo intermedio. |
| `macsec` | `MACSec/` | Comunicación protegida mediante MACsec sobre el segmento Ethernet controlado. Permite evaluar confidencialidad, integridad y sobrecosto en capa 2. |

La estructura de carpetas conserva nombres heredados de las corridas originales para mantener trazabilidad. En texto académico y nuevos resultados se recomienda usar siempre `baseline`, `bridge` y `macsec`.

## Contenido del Repositorio

| Ruta | Descripción |
| --- | --- |
| `scripts/` | Herramientas de medición, caracterización Modbus, cálculo de entropía y generación de gráficas. |
| `Baseline/` | Corridas del escenario de referencia, incluyendo mediciones cortas y una corrida extendida. |
| `Bridge/` | Corridas del escenario con puente transparente y resultados de rendimiento del SBC/puente. |
| `MACSec/` | Corridas del escenario protegido, análisis de entropía y caracterización Modbus bajo MACsec. |
| `ram_figures_all_runs/` | Figuras comparativas de memoria generadas desde `vmstat`/`pidstat`. |
| `docs/` | Contexto académico, metodología, dataset, reproducibilidad, criterios de aceptación y política de publicación. |
| `SANITIZATION_MANIFEST.csv` | Inventario de archivos originales y acción aplicada durante la publicación. |
| `SANITIZATION_SUMMARY.json` | Resumen cuantitativo de la exportación pública sanitizada. |

## Uso Rápido

Instalar dependencias recomendadas en Linux:

```bash
sudo apt update
sudo apt install -y iputils-ping iproute2 sysstat iperf3 tshark tcpdump mtr-tiny nmap openssl procps python3 python3-venv ethtool binutils
python3 -m venv .venv_modbus
source .venv_modbus/bin/activate
pip install --upgrade pip
pip install scapy pandas matplotlib
```

Ejecutar una corrida SCADA/Modbus:

```bash
sudo ./scripts/scada_probe_v1_1_multiiface.sh \
  --label macsec_1h \
  --target <API_PLC_PRIVATE_IP> \
  --port 502 \
  --ifaces <IFACE_SCADA>,<IFACE_API_PLC>,macsec0 \
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

Calcular entropía:

```bash
python3 ./scripts/entropy_calc.py ./capture.pcapng --mode macsec-protected
```

Generar gráficas de RAM:

```bash
python3 ./scripts/graficar_ram_vmstat.py \
  --root . \
  --mem-total-mib <MEM_TOTAL_MIB> \
  --top-n 12
```

La guía completa está en [`docs/SCRIPTS.md`](docs/SCRIPTS.md).

## Lectura de Resultados

Cada corrida del probe contiene, cuando aplica:

- `probe_report.html`: reporte interpretado de la corrida.
- `csv/key_metrics_compact.csv`: métricas principales para comparación rápida.
- `csv/latency_stats.csv` y `csv/latency_samples.csv`: latencia agregada y muestras.
- `csv/network_rates.csv` e `interface_delta.csv`: uso de interfaces.
- `csv/cpu_process_summary.csv`: procesos con mayor consumo de CPU.
- `raw/`: logs saneados de herramientas del sistema.

Cada perfil Modbus contiene:

- `modbus_profile_report.html`: reporte HTML del comportamiento Modbus.
- `csv/modbus_transactions.csv`: transacciones request/response y RTT.
- `csv/modbus_adus.csv`: ADUs Modbus observados.
- `csv/function_summary.csv`: distribución por código de función.
- `csv/endpoint_summary.csv`: pares cliente/servidor.
- `csv/polling_summary.csv`: ciclos de consulta.

## Documentación

- [`docs/ACADEMIC_CONTEXT.md`](docs/ACADEMIC_CONTEXT.md): contexto de tesis, objetivo, hipótesis, topología y alcance.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md): procedimiento experimental y relación entre métricas.
- [`docs/ACCEPTANCE_CRITERIA.md`](docs/ACCEPTANCE_CRITERIA.md): criterios de seguridad, desempeño y repeticiones.
- [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md): convención de nombres, artefactos mínimos y comandos.
- [`docs/DATASET.md`](docs/DATASET.md): estructura de datos publicada.
- [`docs/SCRIPTS.md`](docs/SCRIPTS.md): uso de los scripts incluidos.
- [`docs/PUBLICATION_POLICY.md`](docs/PUBLICATION_POLICY.md): reglas de sanitización y publicación.
- [`docs/PENDING_CONFIRMATIONS.md`](docs/PENDING_CONFIRMATIONS.md): datos técnicos que deben confirmarse antes del cierre final de tesis.

## Política de Publicación

Esta es una versión pública. Los identificadores reales de red, host y usuario fueron reemplazados por marcadores como `PRIVATE_IP_###` y `MAC_ADDR_###`. Las capturas crudas (`.pcap`, `.pcapng`), binarios, payloads, archivos comprimidos y claves se sustituyeron por placeholders.

La sanitización no es el objetivo del repositorio; es una medida para publicar evidencia experimental sin revelar detalles sensibles de la infraestructura. El inventario de publicación está en `SANITIZATION_MANIFEST.csv`.

