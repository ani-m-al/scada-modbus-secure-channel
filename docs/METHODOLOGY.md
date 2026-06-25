# Methodology

## Diseño Experimental

La evaluación compara el comportamiento de una comunicación SCADA/Modbus TCP en tres escenarios:

- `Baseline`: comunicación de referencia sin canal seguro.
- `Bridge`: comunicación a través de un puente/intermediario.
- `MACSec`: comunicación protegida con MACsec.

La comparación separa tres niveles:

- Transporte y red: latencia, conectividad, PMTU, tasas de tráfico y estabilidad TCP.
- Aplicación: funciones Modbus, endpoints, transacciones, RTT y ciclos de sondeo.
- Recursos: CPU, memoria, swap, carga y procesos dominantes.

## Procedimiento de Medición

1. Definir el escenario y fijar la duración de la corrida.
2. Ejecutar `scada_probe_v1.sh` o `scada_probe_v1_1_multiiface.sh` contra el endpoint Modbus.
3. Capturar o conservar PCAP/PCAPNG cuando se requiera caracterización Modbus o cálculo de entropía.
4. Ejecutar `modbus_characterizer_v4.py` sobre la captura Modbus.
5. Ejecutar `entropy_calc.py` sobre las capturas relevantes.
6. Generar o revisar gráficas de RAM con `graficar_ram_vmstat.py`.
7. Comparar escenarios usando los CSV agregados, no solo inspección visual.

## Métricas Principales

| Métrica | Fuente | Uso |
| --- | --- | --- |
| RTT ICMP | `latency_stats.csv` | Referencia de conectividad básica. |
| TCP connect avg/p95/p99 | `tcp_connect_stats.csv` | Costo de establecimiento hacia el servicio Modbus. |
| PMTU aproximada | `pmtu_loss_summary.csv` | Detección de fragmentación o ajuste de MTU. |
| Tasas RX/TX | `network_rates.csv` | Carga de red por interfaz. |
| CPU por proceso | `cpu_process_summary.csv` | Identificación de procesos dominantes. |
| RAM total y por proceso | figuras RAM y CSV de vmstat | Impacto en memoria. |
| Funciones Modbus | `function_summary.csv` | Perfil de operaciones de aplicación. |
| RTT Modbus | `modbus_transactions.csv` | Latencia request/response a nivel de aplicación. |
| Entropía | salida de `entropy_calc.py` o CSV derivados | Evidencia complementaria de confidencialidad. |

## Criterios de Interpretación

El repositorio evita convertir una sola métrica en conclusión absoluta. Para tesis, las conclusiones deben cruzar:

- Latencia de red y RTT Modbus.
- Uso de recursos y estabilidad de la conexión.
- Cambios en entropía cuando se observa tráfico protegido.
- Repetición o duración suficiente de corridas, especialmente las corridas de 1 hora.

La entropía no prueba seguridad criptográfica por sí sola. Sirve como evidencia experimental complementaria: tráfico Modbus en claro tiende a mostrar estructura; tráfico protegido debería aproximarse más a una distribución aleatoria en la porción cifrada.

## Reproducibilidad

Para reproducir una corrida, documentar:

- Escenario (`baseline`, `bridge`, `macsec`).
- Duración e intervalo de muestreo.
- Interfaz o lista de interfaces observadas.
- Puerto de servicio.
- Versión de scripts usada.
- Condiciones del host y topología experimental.

Los identificadores reales no son necesarios en la versión pública; se pueden registrar en la tesis privada o anexos no públicos si la institución lo permite.

