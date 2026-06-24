#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modbus_characterizer_v4.py
Caracterizador pasivo de Modbus TCP para tesis SCADA.

Captura o lee un PCAP una sola vez y genera:
  - CSVs de eventos, transacciones, funciones, endpoints, registros, ciclos de sondeo y estabilidad TCP.
  - HTML autocontenido con KPIs, tablas y graficas.

Uso con captura existente:
  python3 modbus_characterizer_v4.py --pcap captura.pcapng --out resultados_modbus

Uso en vivo:
  sudo python3 modbus_characterizer_v4.py --iface tun0 --duration 300 --out resultados_modbus

Dependencias:
  python3 -m pip install scapy pandas matplotlib
"""

from __future__ import annotations

import argparse
import base64
import csv
import html
import math
import os
import statistics
import struct
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd
    from scapy.all import IP, TCP, Raw, sniff, rdpcap  # type: ignore
except Exception as e:  # pragma: no cover
    print("[ERROR] Faltan dependencias. Instale con:", file=sys.stderr)
    print("  python3 -m pip install scapy pandas matplotlib", file=sys.stderr)
    print(f"Detalle: {type(e).__name__}: {e}", file=sys.stderr)
    raise SystemExit(2)

FC_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    23: "Read/Write Multiple Registers",
}

READ_FCS = {1, 2, 3, 4}
WRITE_FCS = {5, 6, 15, 16, 23}


@dataclass
class ParsedADU:
    frame_index: int
    time_epoch: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    function_base: int
    function_name: str
    is_exception: bool
    exception_code: Optional[int]
    reference_num: Optional[int]
    quantity: Optional[int]
    byte_count: Optional[int]
    value_hex: str
    adu_bytes: int
    tcp_payload_bytes: int
    register_signature: str


def mkdir(path: str | Path) -> str:
    Path(path).mkdir(parents=True, exist_ok=True)
    return str(path)


def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None or x == "":
            return None
        return float(x)
    except Exception:
        return None


def fmt(x: Any, nd: int = 3) -> str:
    if x is None or x == "":
        return ""
    try:
        v = float(x)
    except Exception:
        return str(x)
    if abs(v) >= 1_000_000:
        return f"{v:.2e}"
    if abs(v) >= 100:
        return f"{v:.2f}"
    return f"{v:.{nd}f}"


def parse_modbus_adu_stream(payload: bytes) -> Iterable[Tuple[int, int, int, int, int, bytes, int]]:
    """Yield tuples: offset, tid, proto, length, unit_id, pdu, adu_len.

    TCP may contain multiple Modbus ADUs. This parser walks the payload defensively.
    MBAP header: transaction_id(2), protocol_id(2), length(2), unit_id(1).
    length counts unit_id + PDU bytes.
    """
    off = 0
    plen = len(payload)
    while off + 7 <= plen:
        tid, proto, length = struct.unpack("!HHH", payload[off:off + 6])
        if proto != 0 or length < 2 or length > 260:
            off += 1
            continue
        adu_len = 6 + length
        if off + adu_len > plen:
            break
        unit_id = payload[off + 6]
        pdu = payload[off + 7:off + adu_len]
        if not pdu:
            off += adu_len
            continue
        yield off, tid, proto, length, unit_id, pdu, adu_len
        off += adu_len


def parse_reference_quantity(fc: int, pdu: bytes, direction: str) -> Tuple[Optional[int], Optional[int], Optional[int], str]:
    reference = None
    quantity = None
    byte_count = None
    value_hex = ""

    base_fc = fc & 0x7F
    if fc & 0x80:
        if len(pdu) >= 2:
            value_hex = f"exception={pdu[1]}"
        return reference, quantity, byte_count, value_hex

    # Request formats
    if direction == "query":
        if base_fc in {1, 2, 3, 4, 15, 16} and len(pdu) >= 5:
            reference = struct.unpack("!H", pdu[1:3])[0]
            quantity = struct.unpack("!H", pdu[3:5])[0]
            if base_fc in {15, 16} and len(pdu) >= 6:
                byte_count = pdu[5]
                value_hex = pdu[6:].hex()
        elif base_fc in {5, 6} and len(pdu) >= 5:
            reference = struct.unpack("!H", pdu[1:3])[0]
            quantity = 1
            value_hex = pdu[3:5].hex()
        elif base_fc == 23 and len(pdu) >= 10:
            # Read/Write Multiple Registers request
            reference = struct.unpack("!H", pdu[1:3])[0]
            quantity = struct.unpack("!H", pdu[3:5])[0]
            byte_count = pdu[9] if len(pdu) >= 10 else None
            value_hex = pdu[10:].hex() if len(pdu) > 10 else ""
    else:
        # Response formats
        if base_fc in {1, 2, 3, 4, 15, 16} and len(pdu) >= 2:
            if base_fc in {1, 2, 3, 4}:
                byte_count = pdu[1]
                value_hex = pdu[2:].hex()
            elif base_fc in {15, 16} and len(pdu) >= 5:
                reference = struct.unpack("!H", pdu[1:3])[0]
                quantity = struct.unpack("!H", pdu[3:5])[0]
        elif base_fc in {5, 6} and len(pdu) >= 5:
            reference = struct.unpack("!H", pdu[1:3])[0]
            quantity = 1
            value_hex = pdu[3:5].hex()
        elif base_fc == 23 and len(pdu) >= 2:
            byte_count = pdu[1]
            value_hex = pdu[2:].hex()

    return reference, quantity, byte_count, value_hex


def direction_from_ports(src_port: int, dst_port: int, modbus_port: int) -> str:
    if dst_port == modbus_port:
        return "query"
    if src_port == modbus_port:
        return "response"
    return "unknown"


def packets_from_input(args: argparse.Namespace):
    if args.pcap:
        print(f"[*] Leyendo PCAP: {args.pcap}")
        return list(rdpcap(args.pcap)), "pcap"
    if not args.iface:
        raise SystemExit("Use --iface para captura en vivo o --pcap para captura existente.")
    print(f"[*] Capturando {args.duration}s en {args.iface}, filtro: tcp port {args.port}")
    return list(sniff(iface=args.iface, filter=f"tcp port {args.port}", timeout=args.duration, count=args.max_packets or 0)), "live"


def packet_tcp_rows(pkts: List[Any], port: int) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    seen_seq: set[Tuple[str, str, int, int, int, int]] = set()
    for i, pkt in enumerate(pkts, start=1):
        if IP not in pkt or TCP not in pkt:
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(tcp.payload) if Raw in tcp else b""
        direction = direction_from_ports(int(tcp.sport), int(tcp.dport), port)
        key = (ip.src, ip.dst, int(tcp.sport), int(tcp.dport), int(tcp.seq), len(payload))
        probable_retx = 1 if key in seen_seq and len(payload) > 0 else 0
        seen_seq.add(key)
        rows.append({
            "frame_index": i,
            "time_epoch": float(pkt.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "direction": direction,
            "payload_bytes": len(payload),
            "syn": 1 if tcp.flags & 0x02 else 0,
            "fin": 1 if tcp.flags & 0x01 else 0,
            "rst": 1 if tcp.flags & 0x04 else 0,
            "ack": 1 if tcp.flags & 0x10 else 0,
            "probable_retransmission": probable_retx,
        })
    return pd.DataFrame(rows)


def parse_adus(pkts: List[Any], port: int) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for i, pkt in enumerate(pkts, start=1):
        if IP not in pkt or TCP not in pkt or Raw not in pkt[TCP]:
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        if src_port != port and dst_port != port:
            continue
        direction = direction_from_ports(src_port, dst_port, port)
        payload = bytes(pkt[TCP].payload)
        for off, tid, proto, length, unit_id, pdu, adu_len in parse_modbus_adu_stream(payload):
            fc = int(pdu[0])
            base_fc = fc & 0x7F
            is_exception = bool(fc & 0x80)
            exc_code = int(pdu[1]) if is_exception and len(pdu) >= 2 else None
            ref, qty, byte_count, value_hex = parse_reference_quantity(fc, pdu, direction)
            if ref is None or qty is None:
                signature = ""
            else:
                signature = f"fc{base_fc}:unit{unit_id}:reg{ref}:qty{qty}:server{ip.dst if direction == 'query' else ip.src}"
            rows.append(ParsedADU(
                frame_index=i,
                time_epoch=float(pkt.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                direction=direction,
                transaction_id=tid,
                protocol_id=proto,
                length=length,
                unit_id=unit_id,
                function_code=fc,
                function_base=base_fc,
                function_name=FC_NAMES.get(base_fc, f"FC {base_fc}"),
                is_exception=is_exception,
                exception_code=exc_code,
                reference_num=ref,
                quantity=qty,
                byte_count=byte_count,
                value_hex=value_hex[:256],
                adu_bytes=adu_len,
                tcp_payload_bytes=len(payload),
                register_signature=signature,
            ).__dict__)
    return pd.DataFrame(rows)


def match_transactions(adus: pd.DataFrame) -> pd.DataFrame:
    if adus.empty:
        return pd.DataFrame()

    requests = adus[adus.direction == "query"].copy().sort_values("time_epoch")
    responses = adus[adus.direction == "response"].copy().sort_values("time_epoch")
    used_responses: set[int] = set()
    rows: List[Dict[str, Any]] = []

    # Index responses by likely tuple
    resp_by_key: Dict[Tuple[str, str, int, int, int], List[Tuple[int, pd.Series]]] = defaultdict(list)
    for idx, r in responses.iterrows():
        key = (r.dst_ip, r.src_ip, int(r.transaction_id), int(r.unit_id), int(r.function_base))
        resp_by_key[key].append((idx, r))

    for _, q in requests.iterrows():
        key = (q.src_ip, q.dst_ip, int(q.transaction_id), int(q.unit_id), int(q.function_base))
        candidates = resp_by_key.get(key, [])
        chosen_idx: Optional[int] = None
        chosen_resp: Optional[pd.Series] = None
        for ridx, resp in candidates:
            if ridx in used_responses:
                continue
            if float(resp.time_epoch) >= float(q.time_epoch):
                chosen_idx = ridx
                chosen_resp = resp
                break
        status = "matched" if chosen_resp is not None else "missing_response"
        if chosen_idx is not None:
            used_responses.add(chosen_idx)
        rtt_ms = (float(chosen_resp.time_epoch) - float(q.time_epoch)) * 1000.0 if chosen_resp is not None else None
        rows.append({
            "request_frame": int(q.frame_index),
            "response_frame": int(chosen_resp.frame_index) if chosen_resp is not None else "",
            "client_ip": q.src_ip,
            "server_ip": q.dst_ip,
            "transaction_id": int(q.transaction_id),
            "unit_id": int(q.unit_id),
            "function_code": int(q.function_code),
            "function_base": int(q.function_base),
            "function_name": q.function_name,
            "reference_num": q.reference_num,
            "quantity": q.quantity,
            "register_signature": q.register_signature,
            "request_time_epoch": float(q.time_epoch),
            "response_time_epoch": float(chosen_resp.time_epoch) if chosen_resp is not None else "",
            "rtt_ms": rtt_ms,
            "status": status,
            "is_exception": bool(chosen_resp.is_exception) if chosen_resp is not None else False,
            "exception_code": chosen_resp.exception_code if chosen_resp is not None else "",
            "request_bytes": int(q.adu_bytes),
            "response_bytes": int(chosen_resp.adu_bytes) if chosen_resp is not None else "",
        })

    # Unmatched responses for visibility
    for idx, r in responses.iterrows():
        if idx not in used_responses:
            rows.append({
                "request_frame": "",
                "response_frame": int(r.frame_index),
                "client_ip": r.dst_ip,
                "server_ip": r.src_ip,
                "transaction_id": int(r.transaction_id),
                "unit_id": int(r.unit_id),
                "function_code": int(r.function_code),
                "function_base": int(r.function_base),
                "function_name": r.function_name,
                "reference_num": r.reference_num,
                "quantity": r.quantity,
                "register_signature": r.register_signature,
                "request_time_epoch": "",
                "response_time_epoch": float(r.time_epoch),
                "rtt_ms": "",
                "status": "orphan_response",
                "is_exception": bool(r.is_exception),
                "exception_code": r.exception_code if r.exception_code is not None else "",
                "request_bytes": "",
                "response_bytes": int(r.adu_bytes),
            })
    return pd.DataFrame(rows)


def build_aggregates(adus: pd.DataFrame, tx: pd.DataFrame, tcp: pd.DataFrame, window_sec: float) -> Dict[str, pd.DataFrame]:
    out: Dict[str, pd.DataFrame] = {}

    if not adus.empty:
        out["endpoint_summary"] = adus.groupby(["src_ip", "dst_ip", "direction"], dropna=False).agg(
            adu_count=("frame_index", "size"),
            adu_bytes=("adu_bytes", "sum"),
            tcp_payload_bytes=("tcp_payload_bytes", "sum"),
        ).reset_index().sort_values("adu_count", ascending=False)
        out["function_summary"] = adus.groupby(["function_base", "function_name", "direction"], dropna=False).agg(
            adu_count=("frame_index", "size"),
            adu_bytes=("adu_bytes", "sum"),
        ).reset_index().sort_values("adu_count", ascending=False)
    else:
        out["endpoint_summary"] = pd.DataFrame()
        out["function_summary"] = pd.DataFrame()

    if not tx.empty:
        matched = tx[tx.status == "matched"].copy()
        if not matched.empty:
            out["rtt_by_server"] = matched.groupby(["server_ip", "function_base", "function_name"], dropna=False).agg(
                transactions=("transaction_id", "size"),
                rtt_min_ms=("rtt_ms", "min"),
                rtt_avg_ms=("rtt_ms", "mean"),
                rtt_median_ms=("rtt_ms", "median"),
                rtt_p95_ms=("rtt_ms", lambda s: s.quantile(0.95)),
                rtt_max_ms=("rtt_ms", "max"),
            ).reset_index().sort_values("transactions", ascending=False)
        else:
            out["rtt_by_server"] = pd.DataFrame()

        regs = tx[(tx.status == "matched") & tx.reference_num.notna()].copy()
        if not regs.empty:
            out["register_activity"] = regs.groupby(["server_ip", "unit_id", "function_base", "function_name", "reference_num", "quantity", "register_signature"], dropna=False).agg(
                transactions=("transaction_id", "size"),
                rtt_avg_ms=("rtt_ms", "mean"),
                rtt_p95_ms=("rtt_ms", lambda s: s.quantile(0.95)),
                first_seen=("request_time_epoch", "min"),
                last_seen=("request_time_epoch", "max"),
            ).reset_index().sort_values("transactions", ascending=False)

            polling_rows: List[Dict[str, Any]] = []
            for sig, g in regs.sort_values("request_time_epoch").groupby("register_signature", dropna=False):
                times = [float(x) for x in g.request_time_epoch.tolist() if x != ""]
                if len(times) < 2:
                    continue
                deltas = [b - a for a, b in zip(times[:-1], times[1:])]
                polling_rows.append({
                    "register_signature": sig,
                    "samples": len(deltas),
                    "poll_min_s": min(deltas),
                    "poll_avg_s": statistics.mean(deltas),
                    "poll_median_s": statistics.median(deltas),
                    "poll_p95_s": sorted(deltas)[int(math.ceil(0.95 * len(deltas))) - 1],
                    "poll_max_s": max(deltas),
                    "poll_std_s": statistics.stdev(deltas) if len(deltas) > 1 else 0.0,
                })
            out["polling_summary"] = pd.DataFrame(polling_rows).sort_values("samples", ascending=False) if polling_rows else pd.DataFrame()
        else:
            out["register_activity"] = pd.DataFrame()
            out["polling_summary"] = pd.DataFrame()
    else:
        out["rtt_by_server"] = pd.DataFrame()
        out["register_activity"] = pd.DataFrame()
        out["polling_summary"] = pd.DataFrame()

    if not tcp.empty:
        out["tcp_stability"] = tcp.groupby(["src_ip", "dst_ip", "direction"], dropna=False).agg(
            packets=("frame_index", "size"),
            payload_bytes=("payload_bytes", "sum"),
            syn_count=("syn", "sum"),
            fin_count=("fin", "sum"),
            rst_count=("rst", "sum"),
            probable_retransmissions=("probable_retransmission", "sum"),
        ).reset_index().sort_values("packets", ascending=False)
    else:
        out["tcp_stability"] = pd.DataFrame()

    # Time buckets for volume and function rate
    if not adus.empty:
        t0 = float(adus.time_epoch.min())
        rows: List[Dict[str, Any]] = []
        for _, r in adus.iterrows():
            bucket = int((float(r.time_epoch) - t0) // window_sec)
            rows.append({
                "bucket": bucket,
                "time_start_s": bucket * window_sec,
                "function_base": int(r.function_base),
                "function_name": r.function_name,
                "direction": r.direction,
                "count": 1,
                "bytes": int(r.adu_bytes),
            })
        df = pd.DataFrame(rows)
        out["time_buckets"] = df.groupby(["bucket", "time_start_s", "function_base", "function_name", "direction"], dropna=False).agg(
            adu_count=("count", "sum"), adu_bytes=("bytes", "sum")
        ).reset_index()
    else:
        out["time_buckets"] = pd.DataFrame()

    return out


def build_interpretation(meta: Dict[str, Any], tx: pd.DataFrame, agg: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    total_tx = int(meta.get("transactions", 0) or 0)
    matched = int(meta.get("matched_tx", 0) or 0)
    missing = int(meta.get("missing_responses", 0) or 0)
    exceptions = int(meta.get("exceptions", 0) or 0)
    modbus_adus = int(meta.get("modbus_adus", 0) or 0)

    def add(section: str, item: str, status: str, evidence: str, recommendation: str = ""):
        rows.append({
            "section": section,
            "item": item,
            "status": status,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    if modbus_adus > 0:
        add("Deteccion", "Tramas Modbus", "OK", f"Se detectaron {modbus_adus} ADUs Modbus TCP.", "La captura es valida para caracterizacion semantica del trafico Modbus.")
    else:
        add("Deteccion", "Tramas Modbus", "ERROR", "No se detectaron ADUs Modbus TCP.", "Verificar interfaz, puerto, cifrado o filtro de captura.")

    if total_tx > 0:
        rate = 100.0 * matched / total_tx
        status = "OK" if rate >= 98 else "WARNING" if rate >= 90 else "ERROR"
        add("Transacciones", "Emparejamiento request/response", status, f"{matched}/{total_tx} transacciones emparejadas ({rate:.2f} %).", "Comparar entre baseline y canal seguro. Una caida puede indicar perdida, cierre de sesiones o captura incompleta.")

    if missing > 0:
        status = "WARNING" if missing / max(1, total_tx) < 0.05 else "ERROR"
        add("Transacciones", "Respuestas faltantes", status, f"Se observaron {missing} requests sin respuesta emparejada.", "Revisar timeout de captura, errores TCP, saturacion o paquetes fuera de la ventana capturada.")
    else:
        add("Transacciones", "Respuestas faltantes", "OK", "No se observaron requests sin respuesta emparejada.")

    if exceptions > 0:
        add("Modbus", "Excepciones", "WARNING", f"Se observaron {exceptions} respuestas de excepcion Modbus.", "Identificar exception_code y revisar si corresponde a operacion normal o error de direccion/funcion.")
    else:
        add("Modbus", "Excepciones", "OK", "No se observaron excepciones Modbus.")

    rtt = agg.get("rtt_by_server", pd.DataFrame())
    if not rtt.empty:
        worst = rtt.sort_values("rtt_p95_ms", ascending=False).iloc[0]
        add("Latencia", "Peor p95 por servidor/funcion", "INFO", f"Servidor {worst.server_ip}, {worst.function_name}, p95={float(worst.rtt_p95_ms):.3f} ms.", "Usar este valor como referencia de comportamiento Modbus real, distinto al TCP connect del probe.")

    regs = agg.get("register_activity", pd.DataFrame())
    if not regs.empty:
        top = regs.iloc[0]
        add("Registros", "Registro mas consultado", "INFO", f"{top.register_signature} con {int(top.transactions)} transacciones.", "Sirve para documentar el mapa operativo observado del canal SCADA-API.")

    tcp = agg.get("tcp_stability", pd.DataFrame())
    if not tcp.empty:
        rst = int(tcp.rst_count.sum()) if "rst_count" in tcp else 0
        retx = int(tcp.probable_retransmissions.sum()) if "probable_retransmissions" in tcp else 0
        status = "OK" if rst == 0 and retx == 0 else "WARNING"
        add("TCP", "Estabilidad TCP", status, f"RST={rst}, retransmisiones probables={retx}.", "Valores altos pueden afectar RTT Modbus y continuidad operativa.")

    return pd.DataFrame(rows)


def fig_to_base64() -> str:
    bio = BytesIO()
    plt.tight_layout()
    plt.savefig(bio, format="png", dpi=150, bbox_inches="tight")
    plt.close()
    return base64.b64encode(bio.getvalue()).decode("ascii")


def plot_bar(df: pd.DataFrame, x: str, y: str, title: str, xlabel: str, ylabel: str, top_n: int = 12) -> str:
    if df.empty or x not in df or y not in df:
        return ""
    d = df.copy().head(top_n)
    plt.figure(figsize=(10, max(4, 0.35 * len(d) + 2)))
    plt.barh(d[x].astype(str), d[y].astype(float))
    plt.gca().invert_yaxis()
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    return fig_to_base64()


def build_plots(adus: pd.DataFrame, tx: pd.DataFrame, agg: Dict[str, pd.DataFrame]) -> Dict[str, str]:
    figs: Dict[str, str] = {}

    fs = agg.get("function_summary", pd.DataFrame())
    if not fs.empty:
        fquery = fs[fs.direction == "query"].copy()
        fquery["label"] = fquery["function_base"].astype(str) + " - " + fquery["function_name"].astype(str)
        figs["function_counts"] = plot_bar(fquery.sort_values("adu_count", ascending=False), "label", "adu_count", "Consultas por codigo de funcion", "ADUs", "Funcion")

    ep = agg.get("endpoint_summary", pd.DataFrame())
    if not ep.empty:
        epq = ep[ep.direction == "query"].copy()
        epq["pair"] = epq["src_ip"].astype(str) + " -> " + epq["dst_ip"].astype(str)
        figs["endpoint_counts"] = plot_bar(epq.sort_values("adu_count", ascending=False), "pair", "adu_count", "Pares cliente-servidor Modbus", "ADUs", "Par")

    regs = agg.get("register_activity", pd.DataFrame())
    if not regs.empty:
        regs = regs.head(15).copy()
        regs["label"] = regs["server_ip"].astype(str) + " reg " + regs["reference_num"].astype(int).astype(str) + " q" + regs["quantity"].astype(int).astype(str)
        figs["register_activity"] = plot_bar(regs, "label", "transactions", "Registros/rangos mas consultados", "Transacciones", "Registro")

    rtt = tx[(tx.status == "matched") & tx.rtt_ms.notna()].copy() if not tx.empty else pd.DataFrame()
    if not rtt.empty:
        plt.figure(figsize=(10, 4))
        vals = rtt.rtt_ms.astype(float)
        plt.hist(vals, bins=min(40, max(10, int(math.sqrt(len(vals))))))
        plt.title("Distribucion de RTT Modbus")
        plt.xlabel("RTT [ms]")
        plt.ylabel("Frecuencia")
        figs["rtt_hist"] = fig_to_base64()

        # Time series, downsample if needed
        rtt2 = rtt.sort_values("request_time_epoch").copy()
        t0 = float(rtt2.request_time_epoch.min())
        if len(rtt2) > 1500:
            rtt2 = rtt2.iloc[::max(1, len(rtt2) // 1500)]
        plt.figure(figsize=(11, 4))
        plt.plot(rtt2.request_time_epoch.astype(float) - t0, rtt2.rtt_ms.astype(float), linewidth=0.8)
        plt.title("RTT Modbus en el tiempo")
        plt.xlabel("Tiempo desde inicio [s]")
        plt.ylabel("RTT [ms]")
        figs["rtt_timeseries"] = fig_to_base64()

    tb = agg.get("time_buckets", pd.DataFrame())
    if not tb.empty:
        q = tb[tb.direction == "query"].groupby("time_start_s", as_index=False).adu_count.sum()
        plt.figure(figsize=(11, 4))
        plt.plot(q.time_start_s.astype(float), q.adu_count.astype(float), marker="o", linewidth=1)
        plt.title("Carga Modbus por ventana temporal")
        plt.xlabel("Tiempo desde inicio [s]")
        plt.ylabel("ADUs por ventana")
        figs["time_buckets"] = fig_to_base64()

    polling = agg.get("polling_summary", pd.DataFrame())
    if not polling.empty:
        d = polling.head(15).copy()
        d["label"] = d["register_signature"].astype(str).str.slice(0, 55)
        figs["polling"] = plot_bar(d, "label", "poll_avg_s", "Ciclo promedio de sondeo por registro/rango", "Segundos", "Registro")

    return figs


def df_to_html(df: pd.DataFrame, max_rows: int = 20) -> str:
    if df is None or df.empty:
        return "<p class='muted'>Sin datos disponibles.</p>"
    d = df.head(max_rows).copy()
    for col in d.columns:
        if pd.api.types.is_float_dtype(d[col]):
            d[col] = d[col].map(lambda x: fmt(x))
    return d.to_html(index=False, escape=True, classes="data-table")


def img_tag(b64: str, alt: str) -> str:
    if not b64:
        return "<p class='muted'>Grafica no disponible.</p>"
    return f"<img alt='{html.escape(alt)}' src='data:image/png;base64,{b64}'/>"


def write_html(out_dir: str, meta: Dict[str, Any], interp: pd.DataFrame, agg: Dict[str, pd.DataFrame], figs: Dict[str, str]) -> None:
    report = os.path.join(out_dir, "modbus_profile_report.html")
    kpis = "".join(f"<div class='kpi'><b>{html.escape(str(k))}</b><br>{html.escape(str(v))}</div>" for k, v in meta.items())
    style = """
<style>
body{font-family:Arial,sans-serif;margin:32px;color:#1f2933;line-height:1.45}h1,h2,h3{color:#102a43}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.kpi{border:1px solid #d9e2ec;border-radius:10px;background:#f8fafc;padding:12px}table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0 24px}th,td{border:1px solid #d9e2ec;padding:7px;vertical-align:top}th{background:#eef2f7;text-align:left}.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-weight:bold;font-size:12px}.OK,.ok{background:#dcfce7;color:#166534}.WARNING,.warning{background:#fef3c7;color:#92400e}.ERROR,.error{background:#fee2e2;color:#991b1b}.INFO,.info{background:#e5e7eb;color:#374151}.muted{color:#627d98}img{max-width:100%;border:1px solid #d9e2ec;border-radius:10px;margin:8px 0 24px;background:white}code{background:#eef2f7;padding:2px 4px;border-radius:4px}.section{margin-top:28px}
</style>
"""
    interp_rows = []
    if not interp.empty:
        for _, r in interp.iterrows():
            st = str(r.get("status", "INFO"))
            interp_rows.append(
                f"<tr><td>{html.escape(str(r.get('section','')))}</td>"
                f"<td>{html.escape(str(r.get('item','')))}</td>"
                f"<td><span class='badge {html.escape(st)}'>{html.escape(st)}</span></td>"
                f"<td>{html.escape(str(r.get('evidence','')))}</td>"
                f"<td>{html.escape(str(r.get('recommendation','')))}</td></tr>"
            )
    interp_table = "<table><thead><tr><th>Seccion</th><th>Item</th><th>Estado</th><th>Evidencia</th><th>Recomendacion</th></tr></thead><tbody>" + "".join(interp_rows) + "</tbody></table>"

    doc = f"""<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Caracterizacion Modbus TCP</title>{style}</head><body>
<h1>Caracterizacion pasiva de Modbus TCP</h1>
<p>Reporte generado automaticamente para documentar el comportamiento operativo del trafico Modbus observado.</p>
<div class='grid'>{kpis}</div>

<div class='section'><h2>1. Lectura tecnica</h2>{interp_table}</div>

<div class='section'><h2>2. Funciones Modbus y endpoints</h2>
<h3>Codigos de funcion</h3>{img_tag(figs.get('function_counts',''), 'Codigos de funcion')}{df_to_html(agg.get('function_summary', pd.DataFrame()), 30)}
<h3>Pares cliente-servidor</h3>{img_tag(figs.get('endpoint_counts',''), 'Endpoints')}{df_to_html(agg.get('endpoint_summary', pd.DataFrame()), 30)}
</div>

<div class='section'><h2>3. Latencia Modbus real</h2>
{img_tag(figs.get('rtt_hist',''), 'Histograma RTT')}
{img_tag(figs.get('rtt_timeseries',''), 'RTT en el tiempo')}
{df_to_html(agg.get('rtt_by_server', pd.DataFrame()), 30)}
</div>

<div class='section'><h2>4. Registros y ciclos de sondeo</h2>
{img_tag(figs.get('register_activity',''), 'Registros')}
{df_to_html(agg.get('register_activity', pd.DataFrame()), 40)}
{img_tag(figs.get('polling',''), 'Ciclos de sondeo')}
{df_to_html(agg.get('polling_summary', pd.DataFrame()), 40)}
</div>

<div class='section'><h2>5. Carga temporal y estabilidad TCP</h2>
{img_tag(figs.get('time_buckets',''), 'Carga temporal')}
{df_to_html(agg.get('time_buckets', pd.DataFrame()), 40)}
<h3>Estabilidad TCP</h3>{df_to_html(agg.get('tcp_stability', pd.DataFrame()), 40)}
</div>

<div class='section'><h2>6. Archivos generados</h2>
<ul>
<li><code>csv/modbus_adus.csv</code>: ADUs Modbus detectadas.</li>
<li><code>csv/modbus_transactions.csv</code>: requests/responses emparejados y RTT.</li>
<li><code>csv/register_activity.csv</code>: registros o rangos mas consultados.</li>
<li><code>csv/polling_summary.csv</code>: ciclos de sondeo por registro/rango.</li>
<li><code>csv/function_summary.csv</code>: resumen por codigo de funcion.</li>
<li><code>csv/endpoint_summary.csv</code>: resumen por par origen-destino.</li>
<li><code>csv/tcp_stability.csv</code>: SYN/FIN/RST/retransmisiones probables.</li>
<li><code>csv/run_metadata.csv</code>: metadatos de la corrida.</li>
</ul>
</div>
</body></html>"""
    with open(report, "w", encoding="utf-8") as f:
        f.write(doc)


def write_csvs(out_dir: str, meta: Dict[str, Any], tcp: pd.DataFrame, adus: pd.DataFrame, tx: pd.DataFrame, agg: Dict[str, pd.DataFrame], interp: pd.DataFrame) -> None:
    csvdir = mkdir(os.path.join(out_dir, "csv"))
    tcp.to_csv(os.path.join(csvdir, "tcp_packets.csv"), index=False)
    adus.to_csv(os.path.join(csvdir, "modbus_adus.csv"), index=False)
    tx.to_csv(os.path.join(csvdir, "modbus_transactions.csv"), index=False)
    interp.to_csv(os.path.join(csvdir, "interpretation.csv"), index=False)
    for name, df in agg.items():
        df.to_csv(os.path.join(csvdir, f"{name}.csv"), index=False)
    with open(os.path.join(csvdir, "run_metadata.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["key", "value"])
        for k, v in meta.items():
            w.writerow([k, v])


def main() -> None:
    ap = argparse.ArgumentParser(description="Caracterizacion pasiva de trafico Modbus TCP con salida CSV + HTML.")
    ap.add_argument("--pcap", help="PCAP/PCAPNG existente para analizar.")
    ap.add_argument("--iface", help="Interfaz para captura en vivo.")
    ap.add_argument("--duration", type=float, default=300, help="Duracion de captura en vivo [s].")
    ap.add_argument("--port", type=int, default=502, help="Puerto Modbus TCP. Default: 502.")
    ap.add_argument("--window-sec", type=float, default=5, help="Ventana temporal para carga por intervalo [s].")
    ap.add_argument("--out", help="Directorio de salida. Si se omite, crea modbus_profile_TIMESTAMP.")
    ap.add_argument("--max-packets", type=int, default=0, help="Maximo de paquetes para captura en vivo. 0=sin limite.")
    args = ap.parse_args()

    out_dir = mkdir(args.out or f"modbus_profile_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    pkts, mode = packets_from_input(args)
    tcp = packet_tcp_rows(pkts, args.port)
    adus = parse_adus(pkts, args.port)
    tx = match_transactions(adus)
    agg = build_aggregates(adus, tx, tcp, args.window_sec)

    matched_tx = int((tx.status == "matched").sum()) if not tx.empty else 0
    missing = int((tx.status == "missing_response").sum()) if not tx.empty else 0
    orphan = int((tx.status == "orphan_response").sum()) if not tx.empty else 0
    exceptions = int(tx.is_exception.sum()) if not tx.empty and "is_exception" in tx else 0
    rtt_vals = [float(x) for x in tx.rtt_ms.dropna().tolist()] if not tx.empty and "rtt_ms" in tx else []

    meta: Dict[str, Any] = {
        "mode": mode,
        "iface": args.iface or "",
        "pcap": args.pcap or "",
        "port": args.port,
        "window_sec": args.window_sec,
        "packets_read": len(pkts),
        "tcp_packets": len(tcp),
        "modbus_adus": len(adus),
        "transactions": int((tx.status != "orphan_response").sum()) if not tx.empty else 0,
        "matched_tx": matched_tx,
        "missing_responses": missing,
        "orphan_responses": orphan,
        "exceptions": exceptions,
        "rtt_avg_ms": fmt(statistics.mean(rtt_vals)) if rtt_vals else "",
        "rtt_p95_ms": fmt(sorted(rtt_vals)[int(math.ceil(0.95 * len(rtt_vals))) - 1]) if rtt_vals else "",
        "register_profiles": int(tx.register_signature.nunique()) if not tx.empty and "register_signature" in tx else 0,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    interp = build_interpretation(meta, tx, agg)
    figs = build_plots(adus, tx, agg)
    write_csvs(out_dir, meta, tcp, adus, tx, agg, interp)
    write_html(out_dir, meta, interp, agg, figs)

    print(f"[+] Carpeta: {out_dir}")
    print(f"[+] Reporte: {out_dir}/modbus_profile_report.html")
    print(f"[+] CSV transacciones: {out_dir}/csv/modbus_transactions.csv")


if __name__ == "__main__":
    main()
