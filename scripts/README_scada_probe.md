# Herramientas SCADA/Modbus para tesis

Este paquete contiene dos programas separados:

1. `scada_probe_v1.sh`: mide rendimiento del servidor/canal SCADA.
2. `modbus_characterizer_v4.py`: caracteriza el comportamiento Modbus TCP.

## 1. Preparación en WSL/Ubuntu

```bash
mkdir -p ~/tesis/tools
cp /ruta/al/archivo/scada_probe_v1.sh ~/tesis/tools/
cp /ruta/al/archivo/modbus_characterizer_v4.py ~/tesis/tools/
chmod +x ~/tesis/tools/scada_probe_v1.sh ~/tesis/tools/modbus_characterizer_v4.py
```

Instalar dependencias recomendadas del probe:

```bash
sudo apt update
sudo apt install -y iputils-ping iproute2 sysstat iperf3 tshark tcpdump mtr-tiny nmap openssl procps python3 python3-venv ethtool binutils
```

Instalar dependencias del characterizer en un entorno virtual:

```bash
python3 -m venv ~/tesis/.venv_modbus
source ~/tesis/.venv_modbus/bin/activate
pip install --upgrade pip
pip install scapy pandas matplotlib
```

## 2. Uso del SCADA probe

Ejemplo baseline:

```bash
~/tesis/tools/scada_probe_v1.sh \
  --label baseline \
  --target PRIVATE_IP_021 \
  --port 502 \
  --iface tun0 \
  --duration 300 \
  --out ~/tesis/resultados_scada
```

Ejemplo canal seguro/VPN:

```bash
~/tesis/tools/scada_probe_v1.sh \
  --label vpn \
  --target PRIVATE_IP_021 \
  --port 502 \
  --iface tun0 \
  --duration 300 \
  --out ~/tesis/resultados_scada
```

Salida principal:

```text
probe_report.html
csv/probe_dataset.csv
csv/probe_interpretation.csv
csv/key_metrics_compact.csv
csv/latency_stats.csv
csv/packet_service_counts.csv
csv/cpu_process_summary.csv
csv/interface_delta.csv
```



### Variante opcional: SCADA probe multi-interfaz

Cuando la PC de medición tenga dos interfaces de red activas, por ejemplo una interfaz hacia el lado SCADA/MACsec y otra hacia el lado PLC/API, use la variante:

```text
scada_probe_v1_1_multiiface.sh
```

Esta variante no reemplaza al `scada_probe_v1.sh`; se usa solamente cuando se necesita observar más de una interfaz durante la misma corrida. Las pruebas activas (`ping`, `tracepath`, TCP connect, `nping`, PMTU e `iperf3`) siguen apuntando a un único `--target`, usando la ruta real del sistema operativo. La diferencia es que la captura, los contadores de interfaz y las métricas de tráfico se registran para todas las interfaces indicadas.

Copiar la variante multi-interfaz:

```bash
cp /ruta/al/archivo/scada_probe_v1_1_multiiface.sh ~/tesis/tools/
chmod +x ~/tesis/tools/scada_probe_v1_1_multiiface.sh
```

Antes de ejecutarla, identifique las interfaces disponibles:

```bash
ip -br addr
ip route
```

Ejemplo para una PC/SBC con una interfaz hacia el PLC y otra hacia SCADA/MACsec:

```bash
sudo ~/tesis/tools/scada_probe_v1_1_multiiface.sh \
  --label baseline_multiiface \
  --target PRIVATE_IP_021 \
  --port 502 \
  --ifaces enx105a9524c6e5,eno1,macsec0 \
  --duration 300 \
  --out ~/tesis/resultados_scada
```

También puede usarse `--iface` con lista separada por comas:

```bash
sudo ~/tesis/tools/scada_probe_v1_1_multiiface.sh \
  --label macsec_multiiface \
  --target PRIVATE_IP_021 \
  --port 502 \
  --iface enx105a9524c6e5,eno1,macsec0 \
  --duration 300 \
  --out ~/tesis/resultados_scada
```

Para la configuración de la SBC usada en las pruebas MACsec, los nombres de interfaz esperados son:

```text
enx105a9524c6e5  -> lado PLC/API
eno1             -> interfaz física usada para crear macsec0
macsec0          -> interfaz MACsec
```

La salida conserva el mismo `probe_report.html` y los mismos CSV principales del SCADA probe, pero `interface_delta.csv`, `network_rates.csv`, `packet_service_counts.csv` y `key_metrics_compact.csv` incluyen información diferenciada por interfaz cuando corresponde.

## 3. Uso del Modbus characterizer

Con PCAP existente:

```bash
source ~/tesis/.venv_modbus/bin/activate
python3 ~/tesis/tools/modbus_characterizer_v4.py \
  --pcap /ruta/captura.pcapng \
  --window-sec 5 \
  --out /ruta/salida_modbus
```

Captura en vivo:

```bash
source ~/tesis/.venv_modbus/bin/activate
sudo ~/tesis/.venv_modbus/bin/python3 ~/tesis/tools/modbus_characterizer_v4.py \
  --iface tun0 \
  --duration 300 \
  --port 502 \
  --window-sec 5 \
  --out ~/tesis/resultados_modbus/baseline
```

Salida principal:

```text
modbus_profile_report.html
csv/modbus_adus.csv
csv/modbus_transactions.csv
csv/register_activity.csv
csv/polling_summary.csv
csv/function_summary.csv
csv/endpoint_summary.csv
csv/tcp_stability.csv
csv/run_metadata.csv
```

## 4. Abrir reportes HTML desde WSL

```bash
cmd.exe /c start "" "$(wslpath -w /ruta/al/reporte.html)"
```

## 5. Nota metodológica

- `scada_probe_v1.sh` mide latencia ICMP, latencia TCP connect, CPU, red, PMTU, captura, entropía de payload y métricas de rendimiento.
- `modbus_characterizer_v4.py` mide comportamiento Modbus: códigos de función, endpoints, transacciones request/response, RTT Modbus, registros consultados, ciclos de sondeo, excepciones y estabilidad TCP.
- Si se desea demostrar cifrado, capture también en la interfaz física del túnel. En la interfaz virtual (`tun0`, `wg0`) puede verse Modbus ya desencapsulado.
