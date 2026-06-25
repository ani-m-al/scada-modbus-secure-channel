# Methodology

La metodología evalúa si un canal seguro transparente puede proteger tráfico SCADA/Modbus TCP sin degradar la operación. El diseño compara tres escenarios bajo una carga de aplicación equivalente: `baseline`, `bridge` y `macsec`.

El contexto académico completo está en [`ACADEMIC_CONTEXT.md`](ACADEMIC_CONTEXT.md) y los criterios de aceptación están en [`ACCEPTANCE_CRITERIA.md`](ACCEPTANCE_CRITERIA.md).

## Diseño Experimental

La evaluación separa seguridad, desempeño y continuidad operativa:

- Seguridad: decodificabilidad Modbus, exposición a sniffing, resistencia a manipulación/repetición y entropía de la región protegida.
- Desempeño: RTT ICMP, conexión TCP, RTT Modbus, PMTU, tasas de tráfico y estabilidad TCP.
- Recursos: CPU, RAM, swap, carga del sistema y procesos dominantes.
- Continuidad: ciclos de sondeo, transacciones emparejadas, excepciones, resets y timeouts.

## Escenarios

| Escenario | Descripción | Uso metodológico |
| --- | --- | --- |
| `baseline` | Comunicación SCADA-API/PLC sin canal seguro adicional. | Establece referencia de desempeño y exposición del contenido Modbus. |
| `bridge` | Comunicación atravesando un puente transparente sin cifrado. | Aísla el costo del dispositivo intermedio y su efecto sobre la operación. |
| `macsec` | Comunicación protegida con MACsec en capa 2. | Evalúa confidencialidad, integridad y sobrecosto del canal seguro. |

## Procedimiento de Medición

1. Definir escenario, duración, interfaces observadas y objetivo API/PLC.
2. Ejecutar `scada_probe_v1.sh` o `scada_probe_v1_1_multiiface.sh` contra el endpoint Modbus.
3. Conservar PCAP/PCAPNG en el repositorio privado o generar placeholder para la versión pública.
4. Ejecutar `modbus_characterizer_v4.py` sobre la captura para obtener transacciones, RTT, funciones, endpoints y ciclos de sondeo.
5. Ejecutar `entropy_calc.py` sobre la región metodológicamente correcta: `modbus` para tráfico sin MACsec y `macsec-protected` para tráfico protegido.
6. Generar o revisar gráficas de RAM con `graficar_ram_vmstat.py`.
7. Comparar escenarios usando CSV agregados, reportes HTML y criterios de aceptación; no basar conclusiones en una sola gráfica o una sola muestra.

## Métricas Principales

| Métrica | Fuente | Uso |
| --- | --- | --- |
| RTT ICMP | `latency_stats.csv` | Referencia de conectividad básica. |
| TCP connect avg/p95/p99 | `tcp_connect_stats.csv` | Costo de establecimiento hacia el servicio Modbus. |
| PMTU aproximada | `pmtu_loss_summary.csv` | Detección de fragmentación o ajuste de MTU. |
| Tasas RX/TX | `network_rates.csv` | Carga de red por interfaz. |
| CPU por proceso | `cpu_process_summary.csv` | Identificación de procesos dominantes. |
| RAM total y por proceso | figuras RAM y CSV de `vmstat`/`pidstat` | Impacto en memoria. |
| Funciones Modbus | `function_summary.csv` | Perfil de operaciones de aplicación. |
| RTT Modbus | `modbus_transactions.csv` | Latencia request/response a nivel de aplicación. |
| Ciclo de sondeo | `polling_summary.csv` | Continuidad del patrón operativo. |
| Estabilidad TCP | `tcp_stability.csv` | Retransmisiones, resets y eventos de transporte. |
| Entropía | `entropy_calc.py` y CSV derivados | Evidencia complementaria de confidencialidad. |

## Interpretación

La entropía no prueba seguridad criptográfica por sí sola. Sirve como evidencia experimental complementaria: tráfico Modbus en claro tiende a mostrar estructura, mientras que la región protegida por MACsec debería aproximarse a una distribución aleatoria.

La comparación defendible debe cruzar:

- RTT de red y RTT Modbus.
- Uso de recursos y estabilidad de conexión.
- Decodificabilidad y entropía del tráfico observado.
- Transacciones Modbus emparejadas y ciclos de sondeo.
- Repeticiones por escenario y corridas extendidas.

Si no se completan las repeticiones recomendadas, los resultados deben presentarse como caracterización experimental preliminar.

## Relación con la Tesis

| Capítulo o sección de tesis | Evidencia en el repositorio |
| --- | --- |
| Planteamiento y objetivos | `README.md`, `docs/ACADEMIC_CONTEXT.md` |
| Diseño experimental | `docs/METHODOLOGY.md`, `docs/ACCEPTANCE_CRITERIA.md` |
| Implementación y herramientas | `docs/SCRIPTS.md`, `scripts/` |
| Resultados | `Baseline/`, `Bridge/`, `MACSec/`, `ram_figures_all_runs/` |
| Reproducibilidad | `docs/REPRODUCIBILITY.md`, `SANITIZATION_MANIFEST.csv` |
| Publicación segura | `docs/PUBLICATION_POLICY.md` |

