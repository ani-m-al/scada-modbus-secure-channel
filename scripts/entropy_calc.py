#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pcap_entropy.py

Calcula entropía de Shannon a partir de un archivo PCAP/PCAPNG.

Soporta:
- PCAP clásico
- PCAPNG
- Ethernet
- RAW IP
- Linux Cooked Capture SLL/SLL2
- Payload TCP puerto 502 para Modbus TCP
- Tramas MACsec eth.type 0x88e5

Uso:
    py -3 pcap_entropy.py captura.pcapng
    py -3 pcap_entropy.py captura.pcapng --mode full
    py -3 pcap_entropy.py captura.pcapng --mode no-l2
    py -3 pcap_entropy.py captura.pcapng --mode modbus
    py -3 pcap_entropy.py captura.pcapng --mode macsec-full
    py -3 pcap_entropy.py captura.pcapng --mode macsec-after-eth
    py -3 pcap_entropy.py captura.pcapng --mode macsec-protected
"""

import argparse
import math
import struct
from pathlib import Path
from typing import Iterator, Optional, Tuple, Dict


# LinkType / DLT comunes
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8
ETH_P_MACSEC = 0x88E5


def shannon_entropy(data: bytes) -> float:
    """Calcula entropía de Shannon en bits/byte."""
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    entropy = 0.0

    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)

    return entropy


def read_packets(path: Path) -> Iterator[Tuple[int, bytes]]:
    """
    Devuelve paquetes como tuplas:
        (linktype, frame_bytes)
    """
    data = path.read_bytes()

    if len(data) < 4:
        raise ValueError("Archivo demasiado pequeño.")

    # PCAPNG: Section Header Block 0x0A0D0D0A
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from read_pcapng(data)
        return

    # PCAP clásico
    yield from read_pcap(data)


def read_pcap(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Lector simple de PCAP clásico."""
    if len(data) < 24:
        raise ValueError("PCAP inválido o incompleto.")

    magic = data[:4]

    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Formato no reconocido: no parece PCAP ni PCAPNG.")

    linktype = struct.unpack(endian + "I", data[20:24])[0]

    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16

        if incl_len <= 0 or offset + incl_len > len(data):
            break

        frame = data[offset:offset + incl_len]
        offset += incl_len

        yield linktype, frame


def read_pcapng(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Lector simple de PCAPNG con soporte para Enhanced Packet Block."""
    offset = 0
    endian = "<"
    interfaces = []

    while offset + 12 <= len(data):
        block_type = struct.unpack(endian + "I", data[offset:offset + 4])[0]
        total_len = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]

        if total_len < 12 or offset + total_len > len(data):
            break

        # Section Header Block
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8:offset + 12]
            if struct.unpack("<I", bom)[0] == 0x1A2B3C4D:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == 0x1A2B3C4D:
                endian = ">"
            else:
                raise ValueError("PCAPNG inválido: byte-order magic no reconocido.")

            interfaces = []

        # Interface Description Block
        elif block_type == 0x00000001:
            body = data[offset + 8:offset + total_len - 4]
            if len(body) >= 8:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
                interfaces.append(linktype)

        # Enhanced Packet Block
        elif block_type == 0x00000006:
            body = data[offset + 8:offset + total_len - 4]
            if len(body) >= 20:
                iface_id = struct.unpack(endian + "I", body[0:4])[0]
                cap_len = struct.unpack(endian + "I", body[12:16])[0]
                pkt_data = body[20:20 + cap_len]

                if iface_id < len(interfaces):
                    linktype = interfaces[iface_id]
                else:
                    linktype = LINKTYPE_ETHERNET

                yield linktype, pkt_data

        # Simple Packet Block
        elif block_type == 0x00000003:
            body = data[offset + 8:offset + total_len - 4]
            if len(body) >= 4 and interfaces:
                orig_len = struct.unpack(endian + "I", body[0:4])[0]
                pkt_data = body[4:4 + orig_len]
                yield interfaces[0], pkt_data

        offset += total_len


def ethernet_l3_info(frame: bytes) -> Optional[Tuple[int, int]]:
    """
    Para Ethernet:
        devuelve (ethertype, l3_offset)
    Maneja VLAN simple o QinQ.
    """
    if len(frame) < 14:
        return None

    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    while ethertype in (ETH_P_VLAN, ETH_P_QINQ, 0x9100):
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4

    return ethertype, offset


def get_l3_payload(frame: bytes, linktype: int) -> Optional[Tuple[int, bytes, int]]:
    """
    Devuelve:
        (ethertype, l3_payload, l3_offset_en_frame)

    Para RAW IP, l3_offset = 0.
    """
    if linktype == LINKTYPE_ETHERNET:
        info = ethernet_l3_info(frame)
        if not info:
            return None
        ethertype, l3_offset = info
        return ethertype, frame[l3_offset:], l3_offset

    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not frame:
            return None

        version = frame[0] >> 4
        if version == 4:
            return ETH_P_IP, frame, 0
        if version == 6:
            return ETH_P_IPV6, frame, 0

    if linktype == LINKTYPE_LINUX_SLL:
        # SLL v1: 16 bytes, protocolo en bytes 14:16
        if len(frame) < 16:
            return None
        proto = struct.unpack("!H", frame[14:16])[0]
        return proto, frame[16:], 16

    if linktype == LINKTYPE_LINUX_SLL2:
        # SLL v2: 20 bytes, protocolo en bytes 0:2
        if len(frame) < 20:
            return None
        proto = struct.unpack("!H", frame[0:2])[0]
        return proto, frame[20:], 20

    return None


def extract_tcp_payload_port_502(frame: bytes, linktype: int) -> bytes:
    """Extrae payload TCP de paquetes IPv4/IPv6 con puerto origen o destino 502."""
    info = get_l3_payload(frame, linktype)
    if not info:
        return b""

    ethertype, l3, _ = info

    if ethertype == ETH_P_IP:
        return extract_tcp_payload_ipv4(l3)

    if ethertype == ETH_P_IPV6:
        return extract_tcp_payload_ipv6_basic(l3)

    return b""


def extract_tcp_payload_ipv4(ip: bytes) -> bytes:
    if len(ip) < 20:
        return b""

    version = ip[0] >> 4
    ihl = (ip[0] & 0x0F) * 4

    if version != 4 or ihl < 20 or len(ip) < ihl:
        return b""

    total_len = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]

    if total_len <= 0 or total_len > len(ip):
        total_len = len(ip)

    # Si está fragmentado y no es primer fragmento, no se puede reconstruir aquí.
    frag_field = struct.unpack("!H", ip[6:8])[0]
    frag_offset = frag_field & 0x1FFF
    if frag_offset != 0:
        return b""

    if proto != 6:
        return b""

    tcp = ip[ihl:total_len]
    if len(tcp) < 20:
        return b""

    src_port, dst_port = struct.unpack("!HH", tcp[0:4])

    if src_port != 502 and dst_port != 502:
        return b""

    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return b""

    return tcp[data_offset:]


def extract_tcp_payload_ipv6_basic(ip6: bytes) -> bytes:
    """
    Extrae TCP payload en IPv6 sin procesar cadenas de extension headers.
    Para este proyecto normalmente no será necesario, pero se deja soporte básico.
    """
    if len(ip6) < 40:
        return b""

    version = ip6[0] >> 4
    if version != 6:
        return b""

    payload_len = struct.unpack("!H", ip6[4:6])[0]
    next_header = ip6[6]

    if next_header != 6:
        return b""

    tcp_start = 40
    tcp_end = 40 + payload_len
    tcp = ip6[tcp_start:tcp_end]

    if len(tcp) < 20:
        return b""

    src_port, dst_port = struct.unpack("!HH", tcp[0:4])

    if src_port != 502 and dst_port != 502:
        return b""

    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return b""

    return tcp[data_offset:]


def is_macsec_frame(frame: bytes, linktype: int) -> Optional[Tuple[int, int]]:
    """
    Detecta tramas MACsec.

    Devuelve:
        (macsec_ethertype_offset, macsec_payload_offset)

    macsec_payload_offset es el inicio después de Ethernet/VLAN/SLL,
    es decir, donde comienza SecTAG.
    """
    info = get_l3_payload(frame, linktype)
    if not info:
        return None

    ethertype, _payload, l3_offset = info

    if ethertype == ETH_P_MACSEC:
        return l3_offset - 2, l3_offset

    return None


def append_metric(metrics: Dict[str, bytearray], key: str, data: bytes) -> None:
    if data:
        metrics.setdefault(key, bytearray()).extend(data)


def analyze_pcap(path: Path) -> Dict[str, Dict[str, float]]:
    metrics_bytes: Dict[str, bytearray] = {}

    total_packets = 0
    macsec_packets = 0
    modbus_packets = 0

    for linktype, frame in read_packets(path):
        total_packets += 1

        # 1) Toda la trama capturada
        append_metric(metrics_bytes, "full", frame)

        # 2) Sin encabezado L2, cuando se puede identificar
        l3_info = get_l3_payload(frame, linktype)
        if l3_info:
            _ethertype, l3_payload, _l3_offset = l3_info
            append_metric(metrics_bytes, "no-l2", l3_payload)

        # 3) Payload TCP puerto 502, equivalente a Modbus/TCP observable
        tcp_payload = extract_tcp_payload_port_502(frame, linktype)
        if tcp_payload:
            modbus_packets += 1
            append_metric(metrics_bytes, "modbus", tcp_payload)

        # 4) MACsec
        macsec_info = is_macsec_frame(frame, linktype)
        if macsec_info:
            macsec_packets += 1
            _ethertype_offset, macsec_offset = macsec_info

            append_metric(metrics_bytes, "macsec-full", frame)

            # Después de encabezado Ethernet/SLL/VLAN visible.
            append_metric(metrics_bytes, "macsec-after-eth", frame[macsec_offset:])

            # Aproximación usada para región protegida:
            # Ethernet normal 14 bytes + SecTAG aprox. 16 bytes = 30 bytes.
            # Para capturas con VLAN/SLL, usamos offset L2 + 16.
            protected_offset = macsec_offset + 16
            if len(frame) > protected_offset:
                append_metric(metrics_bytes, "macsec-protected", frame[protected_offset:])

            # Variante fija, útil si quieres reproducir exactamente frame[30:].
            if len(frame) > 30:
                append_metric(metrics_bytes, "macsec-after-30-fixed", frame[30:])

    results = {}

    for key, data in metrics_bytes.items():
        b = bytes(data)
        results[key] = {
            "bytes": len(b),
            "entropy": shannon_entropy(b),
        }

    results["_counts"] = {
        "packets_total": total_packets,
        "packets_modbus_tcp_payload": modbus_packets,
        "packets_macsec": macsec_packets,
    }

    return results


def print_results(results: Dict[str, Dict[str, float]], mode: str) -> None:
    counts = results.get("_counts", {})

    print("\n=== Conteo de paquetes ===")
    print(f"Paquetes totales:              {int(counts.get('packets_total', 0))}")
    print(f"Paquetes TCP payload puerto 502:{int(counts.get('packets_modbus_tcp_payload', 0))}")
    print(f"Tramas MACsec 0x88e5:          {int(counts.get('packets_macsec', 0))}")

    descriptions = {
        "full": "Toda la trama capturada",
        "no-l2": "Sin encabezado L2 cuando es identificable",
        "modbus": "Payload TCP puerto 502, equivalente a contenido Modbus/TCP observable",
        "macsec-full": "Tramas MACsec completas",
        "macsec-after-eth": "MACsec sin encabezado Ethernet/SLL/VLAN",
        "macsec-protected": "Región protegida aproximada: después de Ethernet/SLL/VLAN + SecTAG aprox.",
        "macsec-after-30-fixed": "Región frame[30:] fija, útil para reproducir cálculo anterior",
    }

    keys = [
        "full",
        "no-l2",
        "modbus",
        "macsec-full",
        "macsec-after-eth",
        "macsec-protected",
        "macsec-after-30-fixed",
    ]

    if mode != "all":
        keys = [mode]

    print("\n=== Entropía de Shannon ===")
    print(f"{'Métrica':26} {'Bytes':>14} {'Entropía [bits/byte]':>24}  Descripción")
    print("-" * 100)

    for key in keys:
        if key not in results:
            print(f"{key:26} {'0':>14} {'N/D':>24}  Sin datos para esta métrica")
            continue

        byte_count = int(results[key]["bytes"])
        entropy = results[key]["entropy"]
        print(f"{key:26} {byte_count:14d} {entropy:24.6f}  {descriptions.get(key, '')}")

    print("\nRecomendación de uso:")
    print("- Línea Base / Puente transparente: usa 'modbus'.")
    print("- MACsec: usa 'macsec-protected' o 'macsec-after-30-fixed' si quieres reproducir el cálculo anterior.")
    print("- 'full' no es ideal para comparar cifrado porque incluye encabezados determinísticos.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calcula entropía de Shannon desde PCAP/PCAPNG."
    )

    parser.add_argument(
        "pcap",
        help="Ruta al archivo .pcap o .pcapng"
    )

    parser.add_argument(
        "--mode",
        choices=[
            "all",
            "full",
            "no-l2",
            "modbus",
            "macsec-full",
            "macsec-after-eth",
            "macsec-protected",
            "macsec-after-30-fixed",
        ],
        default="all",
        help="Métrica a mostrar. Por defecto muestra todas."
    )

    args = parser.parse_args()

    path = Path(args.pcap)

    if not path.exists():
        raise SystemExit(f"No existe el archivo: {path}")

    results = analyze_pcap(path)
    print_results(results, args.mode)


if __name__ == "__main__":
    main()