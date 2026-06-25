# Academic Context

## Título

**Diseño e Implementación de un Canal Seguro Transparente para la Comunicación SCADA-API en el Laboratorio de Micro-Red de la Universidad de Cuenca**

## Autores

- Aníbal Martín Macas Villagómez
- Anthony Josué Pallchisaca Valverde

## Modalidad

Proyecto Técnico en el área de Redes de Telecomunicaciones.

## Objetivo General

Implementar un mecanismo de cifrado y autenticación transparente en el canal de comunicación entre el controlador de estación/API y el servidor SCADA de la Micro-Red de la Universidad de Cuenca, con el fin de garantizar la confidencialidad e integridad de la telemetría operativa frente a amenazas internas, validando su impacto sobre el rendimiento y la disponibilidad del sistema.

## Objetivos Específicos

1. Analizar tecnologías de cifrado y protocolos de túneles seguros aplicables a comunicaciones Modbus TCP en entornos SCADA/OT, seleccionando la alternativa que ofrezca el mejor equilibrio entre robustez criptográfica, baja latencia y compatibilidad con la Micro-Red.
2. Diseñar la arquitectura lógica de una solución de seguridad transparente, definiendo direccionamiento, configuración de extremos, esquema de encapsulación y criterios de operación sin modificar, o modificando mínimamente, la topología existente.
3. Implementar el mecanismo seleccionado en el entorno experimental del laboratorio, encapsulando el tráfico operativo SCADA-API/PLC sin alterar la lógica de control ni los puertos originales de comunicación.
4. Evaluar la efectividad de la solución mediante pruebas de confidencialidad, integridad, resistencia a manipulación y desempeño, considerando métricas como decodificabilidad del tráfico, entropía, éxito/fallo de ataques, RTT Modbus, consumo de CPU/RAM y continuidad operativa.

## Pregunta de Investigación

¿Qué mecanismo de cifrado y autenticación resulta más efectivo para asegurar el enlace entre la API/PLC y el servidor SCADA en la Micro-Red de la Universidad de Cuenca, garantizando la confidencialidad e integridad de la telemetría sin degradar el rendimiento operativo del sistema?

## Hipótesis de Trabajo

La implementación de un canal seguro transparente entre el servidor SCADA y la API/PLC reduce la exposición del tráfico Modbus TCP frente a sniffing, manipulación y repetición, sin afectar de forma significativa la latencia, la disponibilidad ni la continuidad operativa del sistema.

De forma operativa, se espera que el canal seguro:

- reduzca la decodificabilidad del tráfico Modbus observable en el enlace protegido;
- incremente la entropía del contenido protegido hasta valores compatibles con tráfico cifrado;
- impida modificaciones transparentes del tráfico por un intermediario no autorizado;
- mantenga el ciclo de sondeo Modbus y la tasa de transacciones funcionales dentro de márgenes aceptables;
- introduzca una sobrecarga de CPU/RAM baja en el dispositivo puente o extremo de seguridad.

## Topología Experimental

La topología representa una comunicación SCADA-API/PLC dentro del Laboratorio de Micro-Red de la Universidad de Cuenca. El servidor SCADA actúa como cliente de supervisión/control y consulta periódicamente variables operativas mediante Modbus TCP. El extremo de campo, denominado API/PLC en el contexto del proyecto, responde dichas consultas en el puerto TCP `502`.

La versión pública usa roles y marcadores en lugar de direcciones reales:

| Rol | Identificador público |
| --- | --- |
| Servidor SCADA | `<SCADA_PRIVATE_IP>` |
| Puente transparente/SBC | `<BRIDGE_PRIVATE_IP>` |
| API/PLC objetivo | `<API_PLC_PRIVATE_IP>` |
| Puerto Modbus TCP | `502` |
| Interfaz VPN o captura remota | `tun0` |
| Interfaz del puente hacia SCADA | `enp2s0` |
| Interfaz del puente hacia API/PLC | `enp1s0` |
| Bridge Linux | `br0` |
| Interfaz MACsec | `macsec0` |

## Escenarios

### `baseline`

Comunicación SCADA-API/PLC sin canal seguro adicional. Este escenario permite caracterizar el comportamiento normal del tráfico Modbus TCP: volumen de paquetes, códigos de función, latencia RTT, ciclo de sondeo, transacciones emparejadas, excepciones y exposición del contenido.

### `bridge`

Comunicación SCADA-API/PLC atravesando un equipo intermedio configurado como puente transparente. Este escenario evalúa el impacto de incorporar un dispositivo inline sin cifrado y establece un punto controlado para captura, observación y pruebas de intermediación.

### `macsec`

Comunicación SCADA-API/PLC protegida mediante MACsec sobre el segmento Ethernet controlado. Este escenario evalúa el impacto de cifrado e integridad en capa 2 sobre el tráfico Modbus TCP, manteniendo transparencia para las aplicaciones SCADA y API/PLC.

## Hardware y Software

### Servidor SCADA

- Equipo físico: estación de operación SCADA del laboratorio.
- Función: cliente de supervisión/control y origen de consultas Modbus TCP.
- Sistema operativo: Windows.
- Software asociado: cliente SCADA/HMI, herramientas de captura/análisis y VPN cuando aplica.

### API/PLC

- Equipo de campo/control usado como servidor Modbus TCP.
- Función: exposición de registros operativos consultados por SCADA.
- Puerto de servicio: TCP `502`.
- Protocolo: Modbus TCP.
- En el banco experimental se ha trabajado con un PLC/API representativo basado en Arduino OPTA para pruebas Modbus TCP.

### Puente Transparente / Dispositivo de Seguridad

- Equipo: SBC o PC Linux con dos interfaces Ethernet.
- Función: puente transparente, punto de captura y extremo de implementación del canal seguro.
- Interfaces públicas documentadas por rol: `enp2s0`, `enp1s0`, `br0` y `macsec0`.

### Host de Medición y Análisis

- Equipo usado para ejecutar scripts de caracterización, procesamiento de capturas y generación de reportes.
- Herramientas principales: Python 3, Wireshark/TShark, PowerShell y scripts propios del repositorio.

Los modelos exactos, versiones de firmware, versión de Windows, kernel Linux y versiones de herramientas se mantienen en [`PENDING_CONFIRMATIONS.md`](PENDING_CONFIRMATIONS.md) hasta su cierre documental.

## Parámetros MACsec Publicables

Estos parámetros describen el diseño técnico sin revelar material criptográfico:

- Tecnología: MACsec / IEEE 802.1AE.
- Capa de operación: capa 2.
- Interfaz segura: `macsec0`.
- EtherType MACsec observado: `0x88E5`.
- Modo de protección: cifrado e integridad del tráfico Ethernet en el enlace protegido.
- Tráfico protegido: Modbus TCP entre SCADA y API/PLC.
- Validación: decodificabilidad, entropía, RTT Modbus, consumo de CPU/RAM y continuidad de transacciones.
- Región usada para entropía: región cifrada después de encabezados Ethernet/MACsec, excluyendo campos no cifrados cuando corresponda.

No se publican claves CAK/SAK, identificadores CKN reales, certificados privados, archivos de configuración con secretos ni comandos históricos que contengan claves.

