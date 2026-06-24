SCADA VPN Probe - Evidencia de medición

Escenario: macsec
Target: PRIVATE_IP_021
Puerto: 502
Interfaz: tun0
Duración: 300 segundos
Inicio: 20260618_121101

Archivos principales:
- probe_report.html: informe interpretado con tablas y graficos embebidos.
- csv/probe_dataset.csv: CSV maestro consolidado para procesamiento automatico.
- csv/probe_interpretation.csv: CSV con lectura tecnica automatica de las metricas.
- csv/packet_service_counts.csv: paquetes por servicio, desde pcap si existe o estimados desde logs.
- csv/latency_samples.csv: muestras individuales de latencia por servicio.
- csv/latency_stats.csv: estadisticos de latencia para boxplots e IC95.
- csv/cpu_process_summary.csv: CPU promedio por proceso y CPU acumulada.
- csv/interface_delta.csv: delta de paquetes y bytes TX/RX en la interfaz.
- csv/network_rates.csv: tasas promedio RX/TX desde sar.
- csv/pmtu_loss_summary.csv: resumen de PMTU y perdida.
- csv/tcp_health_summary.csv: resumen de salud TCP.
- csv/openssl_speed_summary.csv: resumen del benchmark criptografico local.
- metadata.txt: información del host, ruta, interfaz, versiones de herramientas.
- commands.log: comandos ejecutados.
- notes.txt: advertencias y herramientas omitidas.
- csv/summary.csv: resumen principal de métricas.
- csv/tcp_connect_*.csv: muestras individuales de latencia TCP connect.
- raw/: salidas crudas de herramientas.
- pcap/: capturas de tráfico, si tshark/tcpdump tuvo permisos.

Uso metodológico:
1. Ejecutar este script con --label baseline antes de levantar el túnel.
2. Ejecutar el mismo comando, cambiando solo los parámetros necesarios, con --label vpn.
3. Comparar csv/summary.csv entre ambos escenarios.
4. Reportar delta absoluto y delta porcentual:
   delta_abs = valor_vpn - valor_baseline
   delta_pct = ((valor_vpn - valor_baseline) / valor_baseline) * 100

Notas:
- La captura de tráfico puede requerir permisos de root o capacidades especiales.
- iperf3 requiere un servidor iperf3 activo en el extremo remoto: iperf3 -s.
- La prueba TCP connect mide establecimiento de conexión, no transacción Modbus completa.
- La entropía de payload es una evidencia complementaria de confidencialidad, no una prueba criptográfica formal.
- No se modifica la red. Para pruebas con tc/netem se recomienda un script separado y controlado.
