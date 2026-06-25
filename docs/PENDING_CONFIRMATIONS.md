# Pending Confirmations

El contexto académico principal ya está documentado en `ACADEMIC_CONTEXT.md`. Antes del cierre final de tesis conviene confirmar estos datos técnicos para que el repositorio y el documento escrito queden completamente alineados.

## Servidor SCADA

- Modelo exacto del equipo.
- CPU.
- RAM.
- Versión exacta de Windows.
- Versión del software SCADA/HMI.

## API/PLC

- Modelo exacto del PLC/API final usado en la validación.
- Versión de firmware.
- Librería o stack Modbus utilizado.
- Mapa final de registros usado en las pruebas.

## Puente Transparente / Dispositivo de Seguridad

- Modelo exacto de SBC/PC.
- CPU.
- RAM.
- Chipset de red.
- Soporte MACsec por software o hardware.
- Versión de kernel Linux.

## Host de Medición y Análisis

- Versión de Windows.
- Versión de Python.
- Versión de Wireshark/TShark.
- Versión de PowerShell.

## Linux / Puente o Host de Captura

- Distribución Linux.
- Kernel Linux.
- Versión de `iproute2`.
- Versión de `tcpdump`.
- Versión de `tshark` / `dumpcap`.
- Versión de `sar`, `mpstat` y `pidstat`.
- Estado del módulo MACsec Linux.

## Parámetros MACsec Publicables si se Confirman

- Cipher suite usada.
- Longitud de ICV.
- Uso de SCI.
- Política de validación.
- Ventana de replay.
- MTU efectiva.
- Interfaz física padre.
- Modo software/hardware offload.

