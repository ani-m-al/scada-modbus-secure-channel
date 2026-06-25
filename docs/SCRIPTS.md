# Scripts

Esta carpeta reúne las herramientas usadas para levantar evidencia, caracterizar tráfico Modbus y generar resultados derivados.

## `scada_probe_v1.sh`

Probe principal para medir el desempeño de un canal SCADA/Modbus TCP.

Mide:

- Latencia ICMP.
- Latencia TCP connect al puerto industrial.
- PMTU aproximada.
- Conteo y tasas de tráfico.
- CPU, carga, memoria y procesos.
- Captura de tráfico cuando `tshark` o `tcpdump` están disponibles.
- Entropía aproximada del payload TCP cuando aplica.

Ejemplo:

```bash
sudo ./scripts/scada_probe_v1.sh \
  --label baseline \
  --target <TARGET_IP> \
  --port 502 \
  --iface tun0 \
  --duration 300 \
  --out ./results
```

Opciones útiles:

- `--label`: etiqueta del escenario.
- `--target`: IP o hostname del PLC/API/servidor remoto.
- `--port`: puerto TCP, por defecto `502`.
- `--iface`: interfaz a observar.
- `--duration`: duración de la corrida en segundos.
- `--out`: directorio base de salida.
- `--no-capture`, `--no-openssl`, `--no-tcp-connect`, `--no-mtu-test`, `--no-mtr`: desactivan pruebas específicas.

## `scada_probe_v1_1_multiiface.sh`

Variante del probe para observar varias interfaces en una misma corrida. Es la opción preferida cuando el escenario tiene una interfaz física, una interfaz puente y una interfaz MACsec.

Ejemplo:

```bash
sudo ./scripts/scada_probe_v1_1_multiiface.sh \
  --label macsec_1h \
  --target <TARGET_IP> \
  --port 502 \
  --ifaces <IFACE_PLC>,<IFACE_PHY>,macsec0 \
  --duration 3600 \
  --out ./results
```

La diferencia principal frente a `scada_probe_v1.sh` es que `interface_delta.csv`, `network_rates.csv`, `packet_service_counts.csv` y el reporte HTML separan la información por interfaz cuando corresponde.

## `modbus_characterizer_v4.py`

Caracterizador pasivo de Modbus TCP. Puede analizar un PCAP/PCAPNG existente o capturar en vivo desde una interfaz.

Desde captura existente:

```bash
python3 ./scripts/modbus_characterizer_v4.py \
  --pcap ./capture.pcapng \
  --window-sec 5 \
  --out ./results/modbus_profile
```

Captura en vivo:

```bash
sudo ./.venv_modbus/bin/python3 ./scripts/modbus_characterizer_v4.py \
  --iface tun0 \
  --duration 300 \
  --port 502 \
  --window-sec 5 \
  --out ./results/modbus_live
```

Salida principal:

- `modbus_profile_report.html`
- `csv/modbus_adus.csv`
- `csv/modbus_transactions.csv`
- `csv/register_activity.csv`
- `csv/polling_summary.csv`
- `csv/function_summary.csv`
- `csv/endpoint_summary.csv`
- `csv/tcp_stability.csv`
- `csv/run_metadata.csv`

## `entropy_calc.py`

Calcula entropía de Shannon sobre PCAP/PCAPNG. Está pensado para comparar tráfico Modbus estructurado frente a tramas MACsec protegidas.

Ejemplo general:

```bash
python3 ./scripts/entropy_calc.py ./capture.pcapng --mode all
```

Modos disponibles:

- `full`: trama completa.
- `no-l2`: sin encabezado de capa 2.
- `modbus`: payload TCP asociado a Modbus.
- `macsec-full`: trama MACsec completa.
- `macsec-after-eth`: contenido después del encabezado Ethernet.
- `macsec-protected`: porción protegida de MACsec.
- `macsec-after-30-fixed`: modo compatible con cálculos previos.

Recomendación metodológica:

- Para baseline o bridge, usar `modbus`.
- Para MACsec, usar `macsec-protected` o `macsec-after-30-fixed`.
- Evitar comparar únicamente `full`, porque incluye encabezados determinísticos.

## `graficar_ram_vmstat.py`

Genera figuras de RAM desde corridas que contienen `raw/vmstat.log` y, cuando está disponible, `pidstat`.

Ejemplo:

```bash
python3 ./scripts/graficar_ram_vmstat.py \
  --root . \
  --mem-total-mib 24032 \
  --top-n 12
```

Opciones:

- `--root`: directorio raíz de corridas o una corrida específica.
- `--mem-total-mib`: RAM total del host en MiB.
- `--keep-first`: conserva la primera muestra de `vmstat`; por defecto se descarta.
- `--top-n`: número de procesos a mostrar en la gráfica acumulada.

## `ram_all_runs_index.csv`

Índice de figuras de RAM generadas para varias corridas. Sirve como puente entre los resultados por escenario y las figuras consolidadas.

