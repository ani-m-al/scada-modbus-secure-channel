# Acceptance Criteria

Este documento define criterios de aceptación para interpretar si el canal seguro mejora la seguridad sin comprometer la operación SCADA/Modbus.

## Seguridad

El canal seguro se considera aceptable si cumple:

- Decodificabilidad Modbus en el enlace protegido cercana a `0 %` para un observador ubicado fuera del extremo legítimo de descifrado.
- Sniffing: el atacante no puede reconstruir valores Modbus útiles a partir del enlace protegido.
- Manipulación: los intentos de modificación inline no producen cambios válidos aceptados por el extremo receptor.
- Repetición: las tramas reinyectadas no se aceptan como transacciones válidas nuevas.
- Entropía: la región cifrada presenta entropía alta y compatible con tráfico cifrado, idealmente cercana a `8 bits/byte` en el segmento cifrado evaluado.

## Desempeño

El canal seguro se considera aceptable si:

- El RTT Modbus p95 del escenario protegido no supera un umbral operativo definido a partir de la línea base.
- La degradación relativa de RTT p95 se mantiene controlada respecto a línea base.
- No se altera el ciclo de sondeo dominante.
- No aumenta de forma relevante la cantidad de transacciones no emparejadas.
- No se generan resets, timeouts o excepciones Modbus atribuibles al canal seguro.
- El consumo de CPU/RAM del puente o extremo seguro permanece dentro de la capacidad del equipo.
- No se observan pérdidas sostenidas, drops de interfaz ni saturación de colas durante la ventana de prueba.

## Umbrales Recomendados

Estos umbrales son criterios prácticos para el repositorio público. Deben ajustarse si el proceso real de la Micro-Red exige límites más estrictos.

| Métrica | Criterio recomendado |
| --- | --- |
| RTT p95 protegido | `<= 2x` el RTT p95 de línea base |
| RTT p95 protegido absoluto | `<= 50 ms`, salvo justificación por línea base real |
| Transacciones Modbus no emparejadas | `<= 1 %` |
| Degradación de servicio por timeouts/resets | `0 %` o no observable |
| CPU promedio del puente/SBC | `<= 30 %` durante operación normal |
| RAM | Sin crecimiento sostenido durante la ventana de prueba |
| Entropía del segmento cifrado | Cercana a `8 bits/byte` |
| Decodificabilidad Modbus en enlace protegido | `0 %` desde el punto de captura externo al extremo descifrado |

## Repeticiones por Escenario

Para que los resultados sean defendibles, cada escenario debe ejecutarse bajo condiciones comparables:

| Escenario | Repeticiones recomendadas |
| --- | --- |
| `baseline` | Mínimo 3 corridas de 300 s |
| `bridge` | Mínimo 3 corridas de 300 s |
| `macsec` | Mínimo 3 corridas de 300 s |
| Corrida extendida | 1 corrida de 1 h por escenario |
| Corridas largas opcionales | 6 h si se busca evidenciar disponibilidad sostenida |

Las corridas de 300 s permiten capturar suficientes ciclos de sondeo Modbus cuando el patrón dominante es cercano a 1 s. Tres repeticiones por escenario permiten observar variabilidad entre corridas y calcular media, mediana, desviación estándar, p95 e intervalos de confianza. Las corridas de 1 h complementan el análisis al verificar estabilidad temporal, consumo de recursos y continuidad operativa fuera de una ventana corta.

Si no se completan tres repeticiones por escenario, los resultados deben declararse como caracterización experimental preliminar y no como comparación estadística cerrada.

