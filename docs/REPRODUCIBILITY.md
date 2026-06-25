# Reproducibility

Este documento define la convención de nombres, artefactos mínimos y comandos base para reproducir las corridas del proyecto.

## Nombres de Escenarios

Usar siempre estos nombres canónicos:

- `baseline`: comunicación original sin puente ni canal seguro adicional.
- `bridge`: comunicación con puente transparente sin cifrado.
- `macsec`: comunicación con canal seguro MACsec.

En texto académico puede usarse Línea Base, Puente Transparente y MACsec. En archivos, etiquetas y scripts conviene mantener los nombres canónicos para evitar ambigüedad.

## Formato de Corrida

Formato recomendado:

```text
<scenario>_<duration>_<iface>_<target_role>_<YYYYMMDD_HHMMSS>
```

Ejemplos publicables:

```text
baseline_300s_tun0_API_PLC_YYYYMMDD_HHMMSS
bridge_300s_tun0_API_PLC_YYYYMMDD_HHMMSS
macsec_300s_macsec0_API_PLC_YYYYMMDD_HHMMSS
macsec_1h_macsec0_API_PLC_YYYYMMDD_HHMMSS
```

En la versión pública no se deben usar direcciones reales en nombres de carpeta. Si una corrida original contenía una IP, la exportación pública debe reemplazarla por `PRIVATE_IP_###` o por un rol no sensible.

## Estructura Recomendada para Nuevos Resultados

La estructura histórica de este repositorio se conserva por trazabilidad. Para nuevos experimentos se recomienda:

```text
results/
  baseline/
    300s/
    1h/
  bridge/
    300s/
    1h/
  macsec/
    300s/
    1h/

scripts/
  capture/
  characterization/
  plotting/
  attacks/

docs/
  methodology/
  results/
  reproducibility/

figures/
  baseline/
  bridge/
  macsec/

tables/
  baseline/
  bridge/
  macsec/
```

## Archivos Mínimos por Corrida

Cada corrida debe conservar:

- PCAP/PCAPNG en repositorio privado o placeholder en repositorio público.
- CSV de resumen.
- CSV de transacciones Modbus.
- CSV de RTT.
- CSV de códigos de función.
- CSV de consumo CPU/RAM.
- Reporte HTML generado.
- Archivo `summary.env`, `metadata.txt` o `metadata.json` con parámetros de ejecución.
- Gráficas finales en PNG/PDF/SVG, según corresponda.

## Captura de Métricas

Ejemplo para una corrida de línea base:

```bash
sudo ./scripts/scada_probe_v1.sh \
  --label baseline_300s \
  --target <API_PLC_PRIVATE_IP> \
  --port 502 \
  --iface tun0 \
  --duration 300 \
  --out ./results/baseline/300s
```

Ejemplo para un escenario con varias interfaces:

```bash
sudo ./scripts/scada_probe_v1_1_multiiface.sh \
  --label macsec_300s \
  --target <API_PLC_PRIVATE_IP> \
  --port 502 \
  --ifaces enp2s0,enp1s0,br0,macsec0 \
  --duration 300 \
  --out ./results/macsec/300s
```

## Caracterización Modbus

```bash
python3 ./scripts/modbus_characterizer_v4.py \
  --pcap ./capture.pcapng \
  --port 502 \
  --window-sec 5 \
  --out ./results/<scenario>/modbus_profile
```

## Entropía

Para baseline y bridge:

```bash
python3 ./scripts/entropy_calc.py ./capture.pcapng --mode modbus
```

Para MACsec:

```bash
python3 ./scripts/entropy_calc.py ./capture.pcapng --mode macsec-protected
```

## Citación y Trazabilidad

Para tesis y publicaciones, citar resultados por:

- escenario;
- duración;
- interfaz;
- rol objetivo;
- fecha/hora de corrida;
- script usado;
- commit o release del repositorio;
- hash del archivo cuando esté permitido publicar el artefacto.

Ejemplo de referencia interna:

```text
Escenario: macsec
Duración: 300 s
Interfaz: macsec0
Objetivo: API/PLC, puerto 502
Herramienta: scada_probe_v1_1_multiiface.sh + modbus_characterizer_v4.py
Repositorio: commit <COMMIT_HASH>
```

