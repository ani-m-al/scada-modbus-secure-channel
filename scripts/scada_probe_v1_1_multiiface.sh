#!/usr/bin/env bash
# scada_probe_v1_1_multiiface.sh
# Versión: 1.0
#
# Objetivo:
#   Levantar un log replicable para medir rendimiento del servidor/canal SCADA y comparar baseline vs escenario con túnel seguro
#   en una comunicación SCADA-PLC/API.
#
# Características:
#   - Read-only por defecto: no modifica rutas, MTU, qdisc ni firewall.
#   - Genera carpeta de evidencia con logs crudos, CSV, metadatos, CSV consolidado e informe HTML interpretado.
#   - Usa herramientas Linux comunes si están instaladas: ping, tracepath, mtr, nping,
#     iperf3, tshark/tcpdump, sar, mpstat, pidstat, vmstat, ss, nstat, openssl.
#
# Ejemplo baseline:
#   ./scada_vpn_probe.sh --label baseline --target PRIVATE_IP_007 --port 502 --iface eth0 --duration 300
#
# Ejemplo VPN:
#   ./scada_vpn_probe.sh --label vpn --target PRIVATE_IP_003 --port 502 --iface wg0 --duration 300
#
# Ejemplo con iperf3:
#   ./scada_vpn_probe.sh --label vpn --target PRIVATE_IP_003 --port 502 --iface wg0 --duration 300 --iperf-server PRIVATE_IP_003
#
# Ejemplo midiendo un proceso VPN o SCADA:
#   ./scada_vpn_probe.sh --label vpn --target PRIVATE_IP_003 --port 502 --iface wg0 --duration 300 --pid 1234
#
# Requisitos recomendados:
#   sudo apt install iputils-ping iproute2 sysstat iperf3 tshark tcpdump mtr-tiny nmap openssl procps
#
set -u
set -o pipefail

VERSION="1.1-multiiface"

LABEL="baseline"
TARGET=""
PORT="502"
IFACE=""
DURATION="300"
INTERVAL="1"
PING_INTERVAL="0.2"
PING_SIZE="56"
IPERF_SERVER=""
PID_TO_MONITOR=""
OUT_BASE="./scada_vpn_probe_results"
ENABLE_CAPTURE="1"
ENABLE_OPENSSL="1"
ENABLE_TCP_CONNECT="1"
ENABLE_MTU_TEST="1"
ENABLE_MTR="1"

usage() {
  cat <<'USAGE'
Uso:
  ./scada_vpn_probe.sh --target IP [opciones]

Opciones obligatorias:
  --target IP                 IP o hostname del PLC/API/servidor remoto.

Opciones principales:
  --label baseline|vpn|texto  Etiqueta del escenario. Default: baseline.
  --port N                    Puerto TCP industrial. Default: 502.
  --iface IFACE[,IFACE2]      Interfaz o lista de interfaces a observar/capturar. Si se omite, se infiere por ruta hacia target.
  --ifaces IF1,IF2             Alias de --iface para PCs con dos o más interfaces.
  --duration SEG              Duración de monitores y pruebas principales. Default: 300.
  --interval SEG              Intervalo de muestreo para sar/mpstat/pidstat/vmstat. Default: 1.
  --out DIR                   Directorio base de resultados. Default: ./scada_vpn_probe_results.

Opciones de pruebas:
  --iperf-server IP           Ejecuta iperf3 contra este servidor, si está disponible.
  --pid PID                   Mide CPU/RAM/I/O/cambios de contexto de este proceso con pidstat.
  --no-capture                No intenta capturar tráfico con tshark/tcpdump.
  --no-openssl                No ejecuta openssl speed.
  --no-tcp-connect            No mide latencia TCP connect con python3.
  --no-mtu-test               No ejecuta prueba PMTU con ping -M do.
  --no-mtr                    No ejecuta mtr.

Ejemplos:
  ./scada_vpn_probe.sh --label baseline --target PRIVATE_IP_006 --port 502 --iface eth0 --duration 300
  ./scada_vpn_probe.sh --label vpn --target PRIVATE_IP_004 --port 502 --iface wg0 --duration 300 --iperf-server PRIVATE_IP_004
USAGE
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

ts() {
  date +"%Y-%m-%dT%H:%M:%S%z"
}

safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --label) LABEL="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --iface) IFACE="${2:-}"; shift 2 ;;
    --ifaces) IFACE="${2:-}"; shift 2 ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --out) OUT_BASE="${2:-}"; shift 2 ;;
    --iperf-server) IPERF_SERVER="${2:-}"; shift 2 ;;
    --pid) PID_TO_MONITOR="${2:-}"; shift 2 ;;
    --no-capture) ENABLE_CAPTURE="0"; shift ;;
    --no-openssl) ENABLE_OPENSSL="0"; shift ;;
    --no-tcp-connect) ENABLE_TCP_CONNECT="0"; shift ;;
    --no-mtu-test) ENABLE_MTU_TEST="0"; shift ;;
    --no-mtr) ENABLE_MTR="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción no reconocida: $1" ;;
  esac
done

[ -n "$TARGET" ] || { usage; die "Falta --target"; }

case "$DURATION" in
  ''|*[!0-9]*) die "--duration debe ser entero en segundos" ;;
esac
case "$INTERVAL" in
  ''|*[!0-9]*) die "--interval debe ser entero en segundos" ;;
esac
case "$PORT" in
  ''|*[!0-9]*) die "--port debe ser entero" ;;
esac

if [ -z "$IFACE" ]; then
  IFACE="$(ip route get "$TARGET" 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
fi
[ -n "$IFACE" ] || die "No se pudo inferir interfaz. Use --iface o --ifaces."

# Normaliza lista de interfaces. Ejemplos validos:
#   --iface eth0
#   --iface eth0,eth1
#   --ifaces eth0,eth1
IFACE_SPEC="$(printf '%s' "$IFACE" | tr ',' ' ' | xargs)"
[ -n "$IFACE_SPEC" ] || die "Lista de interfaces vacia."
PRIMARY_IFACE="$(printf '%s
' $IFACE_SPEC | head -n 1)"
IFACE_LABEL="$(safe_name "$(printf '%s' "$IFACE_SPEC" | tr ' ' '_')")"

# Validacion temprana: evita reportes vacios cuando una interfaz no existe.
for _iface in $IFACE_SPEC; do
  if [ ! -d "/sys/class/net/$_iface" ] && ! ip link show dev "$_iface" >/dev/null 2>&1; then
    echo "[ERROR] La interfaz '$_iface' no existe en este host." >&2
    echo "[INFO] Interfaces disponibles:" >&2
    ip -br addr 2>/dev/null >&2 || true
    echo "[INFO] Ruta calculada hacia $TARGET:" >&2
    ip route get "$TARGET" 2>/dev/null >&2 || true
    die "Use interfaces existentes o levante primero el tunel/interfaz correspondiente."
  fi
done

START_STAMP="$(date +"%Y%m%d_%H%M%S")"
RUN_ID="$(safe_name "${LABEL}_${TARGET}_${IFACE_LABEL}_${START_STAMP}")"
OUT_DIR="${OUT_BASE}/${RUN_ID}"
RAW_DIR="${OUT_DIR}/raw"
PCAP_DIR="${OUT_DIR}/pcap"
CSV_DIR="${OUT_DIR}/csv"

mkdir -p "$RAW_DIR" "$PCAP_DIR" "$CSV_DIR" || die "No se pudo crear $OUT_DIR"

SUMMARY="${CSV_DIR}/summary.csv"
COMMANDS_LOG="${OUT_DIR}/commands.log"
META="${OUT_DIR}/metadata.txt"
NOTES="${OUT_DIR}/notes.txt"
REPORT_CSV="${CSV_DIR}/probe_dataset.csv"
INTERPRETATION_CSV="${CSV_DIR}/probe_interpretation.csv"
HTML_REPORT="${OUT_DIR}/probe_report.html"

echo "scenario,metric,value,unit,source_file,notes" > "$SUMMARY"
: > "$COMMANDS_LOG"
: > "$NOTES"

add_metric() {
  # $1 metric, $2 value, $3 unit, $4 source, $5 notes
  local metric="$1"
  local value="$2"
  local unit="$3"
  local source_file="$4"
  local notes="${5:-}"
  printf '%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$LABEL")" \
    "$(csv_escape "$metric")" \
    "$(csv_escape "$value")" \
    "$(csv_escape "$unit")" \
    "$(csv_escape "$source_file")" \
    "$(csv_escape "$notes")" >> "$SUMMARY"
}

csv_escape() {
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

log_cmd() {
  echo "[$(ts)] $*" >> "$COMMANDS_LOG"
}

run_to_file() {
  # run_to_file output_file command...
  local outfile="$1"
  shift
  log_cmd "$* > $outfile 2>&1"
  "$@" > "$outfile" 2>&1
  local rc=$?
  echo "[exit_code=$rc]" >> "$outfile"
  return "$rc"
}

run_timeout_to_file() {
  # run_timeout_to_file seconds output_file command...
  local seconds="$1"
  local outfile="$2"
  shift 2
  log_cmd "timeout $seconds $* > $outfile 2>&1"
  timeout "$seconds" "$@" > "$outfile" 2>&1
  local rc=$?
  echo "[exit_code=$rc]" >> "$outfile"
  return "$rc"
}

start_bg() {
  # start_bg name command...
  local name="$1"
  shift
  local outfile="${RAW_DIR}/${name}.log"
  log_cmd "$* > $outfile 2>&1 &"
  "$@" > "$outfile" 2>&1 &
  local pid=$!
  BG_PIDS="${BG_PIDS:-} $pid"
  echo "$pid:$name:$outfile" >> "${OUT_DIR}/background_pids.txt"
}

stop_bg() {
  if [ -n "${BG_PIDS:-}" ]; then
    for p in $BG_PIDS; do
      if kill -0 "$p" >/dev/null 2>&1; then
        kill "$p" >/dev/null 2>&1 || true
      fi
    done
    sleep 1
    for p in $BG_PIDS; do
      if kill -0 "$p" >/dev/null 2>&1; then
        kill -9 "$p" >/dev/null 2>&1 || true
      fi
    done
  fi
}

trap 'echo "[WARN] Interrumpido. Cerrando monitores..." >&2; stop_bg; exit 130' INT TERM

write_metadata() {
  {
    echo "script_version=$VERSION"
    echo "scenario_label=$LABEL"
    echo "target=$TARGET"
    echo "port=$PORT"
    echo "iface=$IFACE_SPEC"
    echo "primary_iface=$PRIMARY_IFACE"
    echo "duration_seconds=$DURATION"
    echo "interval_seconds=$INTERVAL"
    echo "ping_interval_seconds=$PING_INTERVAL"
    echo "ping_size_bytes=$PING_SIZE"
    echo "iperf_server=$IPERF_SERVER"
    echo "pid_to_monitor=$PID_TO_MONITOR"
    echo "start_time=$(ts)"
    echo
    echo "## Host"
    hostnamectl 2>/dev/null || hostname
    echo
    echo "## Kernel"
    uname -a
    echo
    echo "## Date"
    date -Ins
    echo
    echo "## Time sync"
    timedatectl 2>/dev/null || true
    chronyc tracking 2>/dev/null || true
    ntpq -p 2>/dev/null || true
    echo
    echo "## Route to target"
    ip route get "$TARGET" 2>/dev/null || true
    echo
    echo "## Interface details"
    for _iface in $IFACE_SPEC; do
      echo "### $_iface"
      ip -br addr show dev "$_iface" 2>/dev/null || true
      ip link show dev "$_iface" 2>/dev/null || true
      ethtool "$_iface" 2>/dev/null || true
      echo
    done
    echo
    echo "## Tool versions"
    for tool in ping tracepath mtr nping hping3 iperf3 tshark tcpdump sar mpstat pidstat vmstat ss nstat openssl python3 mbpoll modpoll wg openvpn ipsec strongswan; do
      if have "$tool"; then
        echo "### $tool"
        "$tool" --version 2>&1 | head -n 3 || "$tool" -V 2>&1 | head -n 3 || true
      else
        echo "### $tool: NOT_FOUND"
      fi
    done
  } > "$META" 2>&1
}

collect_before_snapshots() {
  : > "${RAW_DIR}/ip_s_link_before.log"
  for _iface in $IFACE_SPEC; do
    run_to_file "${RAW_DIR}/ip_s_link_before_${_iface}.log" ip -s link show dev "$_iface" || true
    { echo "### $_iface"; cat "${RAW_DIR}/ip_s_link_before_${_iface}.log" 2>/dev/null || true; echo; } >> "${RAW_DIR}/ip_s_link_before.log"
  done
  if have ss; then run_to_file "${RAW_DIR}/ss_before.log" ss -ti dst "$TARGET" || true; fi
  if have nstat; then run_to_file "${RAW_DIR}/nstat_before.log" nstat -az || true; fi
  if [ -n "$PID_TO_MONITOR" ] && [ -d "/proc/$PID_TO_MONITOR" ]; then
    run_to_file "${RAW_DIR}/proc_${PID_TO_MONITOR}_status_before.log" cat "/proc/$PID_TO_MONITOR/status" || true
    run_to_file "${RAW_DIR}/proc_${PID_TO_MONITOR}_io_before.log" cat "/proc/$PID_TO_MONITOR/io" || true
  fi
}

collect_after_snapshots() {
  : > "${RAW_DIR}/ip_s_link_after.log"
  for _iface in $IFACE_SPEC; do
    run_to_file "${RAW_DIR}/ip_s_link_after_${_iface}.log" ip -s link show dev "$_iface" || true
    { echo "### $_iface"; cat "${RAW_DIR}/ip_s_link_after_${_iface}.log" 2>/dev/null || true; echo; } >> "${RAW_DIR}/ip_s_link_after.log"
  done
  if have ss; then run_to_file "${RAW_DIR}/ss_after.log" ss -ti dst "$TARGET" || true; fi
  if have nstat; then run_to_file "${RAW_DIR}/nstat_after.log" nstat -az || true; fi
  if [ -n "$PID_TO_MONITOR" ] && [ -d "/proc/$PID_TO_MONITOR" ]; then
    run_to_file "${RAW_DIR}/proc_${PID_TO_MONITOR}_status_after.log" cat "/proc/$PID_TO_MONITOR/status" || true
    run_to_file "${RAW_DIR}/proc_${PID_TO_MONITOR}_io_after.log" cat "/proc/$PID_TO_MONITOR/io" || true
  fi
}

start_monitors() {
  echo "[INFO] Iniciando monitores por ${DURATION}s..."
  if have sar; then
    start_bg "sar_net_dev" sar -n DEV,EDEV,TCP,ETCP "$INTERVAL" "$DURATION"
    start_bg "sar_cpu" sar -u ALL "$INTERVAL" "$DURATION"
    start_bg "sar_load" sar -q "$INTERVAL" "$DURATION"
  else
    echo "sar no instalado; omitiendo sysstat." >> "$NOTES"
  fi

  if have mpstat; then
    start_bg "mpstat_all" mpstat -P ALL "$INTERVAL" "$DURATION"
  else
    echo "mpstat no instalado; omitiendo CPU por nucleo." >> "$NOTES"
  fi

  if have vmstat; then
    start_bg "vmstat" vmstat "$INTERVAL" "$DURATION"
  fi

  if have pidstat; then
    if [ -n "$PID_TO_MONITOR" ]; then
      start_bg "pidstat_${PID_TO_MONITOR}" pidstat -p "$PID_TO_MONITOR" -rudw "$INTERVAL" "$DURATION"
    else
      # Top de procesos puede ser voluminoso, pero ayuda a atribuir carga durante la prueba.
      start_bg "pidstat_all" pidstat -rudw "$INTERVAL" "$DURATION"
    fi
  else
    echo "pidstat no instalado; omitiendo medicion por proceso." >> "$NOTES"
  fi
}

start_capture() {
  [ "$ENABLE_CAPTURE" = "1" ] || return 0

  local capture_filter="host ${TARGET} or tcp port ${PORT} or udp port ${PORT} or icmp"
  : > "${OUT_DIR}/pcap_file.txt"

  for cap_iface in $IFACE_SPEC; do
    local safe_iface
    safe_iface="$(safe_name "$cap_iface")"
    local pcap="${PCAP_DIR}/${LABEL}_${TARGET}_${PORT}_${safe_iface}.pcapng"

    if have tshark; then
      echo "[INFO] Intentando captura con tshark en ${cap_iface}..."
      log_cmd "timeout $DURATION tshark -i $cap_iface -f '$capture_filter' -w $pcap"
      timeout "$DURATION" tshark -i "$cap_iface" -f "$capture_filter" -w "$pcap" > "${RAW_DIR}/tshark_capture_${safe_iface}.log" 2>&1 &
      local cap_pid=$!
      BG_PIDS="${BG_PIDS:-} $cap_pid"
      echo "$cap_pid:tshark_capture_${safe_iface}:${RAW_DIR}/tshark_capture_${safe_iface}.log" >> "${OUT_DIR}/background_pids.txt"
      echo "$pcap" >> "${OUT_DIR}/pcap_file.txt"
    elif have tcpdump; then
      echo "[INFO] Intentando captura con tcpdump en ${cap_iface}..."
      local pcap_tcpdump="${PCAP_DIR}/${LABEL}_${TARGET}_${PORT}_${safe_iface}.pcap"
      log_cmd "timeout $DURATION tcpdump -i $cap_iface -w $pcap_tcpdump $capture_filter"
      timeout "$DURATION" tcpdump -i "$cap_iface" -w "$pcap_tcpdump" $capture_filter > "${RAW_DIR}/tcpdump_capture_${safe_iface}.log" 2>&1 &
      local cap_pid=$!
      BG_PIDS="${BG_PIDS:-} $cap_pid"
      echo "$cap_pid:tcpdump_capture_${safe_iface}:${RAW_DIR}/tcpdump_capture_${safe_iface}.log" >> "${OUT_DIR}/background_pids.txt"
      echo "$pcap_tcpdump" >> "${OUT_DIR}/pcap_file.txt"
    else
      echo "No se encontro tshark ni tcpdump; no se capturo trafico." >> "$NOTES"
      break
    fi
  done
}

run_ping_test() {
  if ! have ping; then
    echo "ping no instalado; omitiendo RTT ICMP." >> "$NOTES"
    return 0
  fi

  local count
  count="$(awk -v d="$DURATION" -v i="$PING_INTERVAL" 'BEGIN { printf "%d", d / i }')"
  [ "$count" -lt 10 ] && count=10

  echo "[INFO] Ejecutando ping: count=${count}, interval=${PING_INTERVAL}, size=${PING_SIZE}"
  run_to_file "${RAW_DIR}/ping_${TARGET}.log" ping -D -i "$PING_INTERVAL" -s "$PING_SIZE" -c "$count" "$TARGET" || true
}

run_trace_tests() {
  if have tracepath; then
    run_to_file "${RAW_DIR}/tracepath_${TARGET}.log" tracepath "$TARGET" || true
  else
    echo "tracepath no instalado; omitiendo PMTU por tracepath." >> "$NOTES"
  fi

  if [ "$ENABLE_MTR" = "1" ]; then
    if have mtr; then
      local cycles=100
      [ "$DURATION" -lt 100 ] && cycles="$DURATION"
      run_to_file "${RAW_DIR}/mtr_${TARGET}.log" mtr -r -c "$cycles" "$TARGET" || true
    else
      echo "mtr no instalado; omitiendo reporte de ruta." >> "$NOTES"
    fi
  fi
}

run_pmtu_test() {
  [ "$ENABLE_MTU_TEST" = "1" ] || return 0
  if ! have ping; then
    echo "ping no instalado; omitiendo prueba PMTU." >> "$NOTES"
    return 0
  fi

  local outfile="${RAW_DIR}/pmtu_ping_M_do.log"
  : > "$outfile"
  echo "[INFO] Ejecutando prueba PMTU aproximada con ping -M do..."

  # Tamaños de payload ICMP. En IPv4, payload 1472 + 28 bytes = MTU 1500.
  # En VPN es común que falle arriba de 1360-1420, dependiendo de encapsulación.
  local sizes="1200 1280 1320 1360 1380 1400 1420 1440 1460 1472"
  local best=""
  for s in $sizes; do
    echo "## size=$s" >> "$outfile"
    log_cmd "ping -M do -s $s -c 3 $TARGET >> $outfile"
    if ping -M do -s "$s" -c 3 "$TARGET" >> "$outfile" 2>&1; then
      best="$s"
    fi
    echo >> "$outfile"
  done

  if [ -n "$best" ]; then
    local approx_mtu=$((best + 28))
    add_metric "pmtu_payload_max_success" "$best" "bytes_icmp_payload" "raw/pmtu_ping_M_do.log" "Mayor payload ICMP exitoso en lista fija."
    add_metric "pmtu_ipv4_approx" "$approx_mtu" "bytes" "raw/pmtu_ping_M_do.log" "Aproximacion IPv4: payload + 28 bytes."
  fi
}

run_tcp_connect_test() {
  [ "$ENABLE_TCP_CONNECT" = "1" ] || return 0
  if ! have python3; then
    echo "python3 no instalado; omitiendo latencia TCP connect." >> "$NOTES"
    return 0
  fi

  local outfile="${CSV_DIR}/tcp_connect_${TARGET}_${PORT}.csv"
  local samples
  samples="$(awk -v d="$DURATION" 'BEGIN { s=d; if (s>600) s=600; if (s<30) s=30; printf "%d", s }')"

  echo "[INFO] Midiendo latencia TCP connect contra ${TARGET}:${PORT} con ${samples} muestras..."
  log_cmd "python3 tcp_connect inline > $outfile"
  python3 - "$TARGET" "$PORT" "$samples" "$outfile" <<'PY'
import csv
import socket
import statistics
import sys
import time

target = sys.argv[1]
port = int(sys.argv[2])
samples = int(sys.argv[3])
outfile = sys.argv[4]

timeout = 2.0
interval = 0.2

rows = []
for i in range(samples):
    t0 = time.perf_counter_ns()
    ok = 0
    err = ""
    try:
        s = socket.create_connection((target, port), timeout=timeout)
        ok = 1
        s.close()
    except Exception as e:
        err = type(e).__name__ + ":" + str(e)
    t1 = time.perf_counter_ns()
    rtt_ms = (t1 - t0) / 1_000_000.0
    rows.append({
        "sample": i + 1,
        "epoch": time.time(),
        "target": target,
        "port": port,
        "ok": ok,
        "tcp_connect_ms": f"{rtt_ms:.6f}",
        "error": err
    })
    time.sleep(interval)

with open(outfile, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["sample", "epoch", "target", "port", "ok", "tcp_connect_ms", "error"])
    w.writeheader()
    w.writerows(rows)
PY
}

run_nping_or_hping() {
  if have nping; then
    local outfile="${RAW_DIR}/nping_tcp_${TARGET}_${PORT}.log"
    local count
    count="$(awk -v d="$DURATION" 'BEGIN { c=d*5; if (c>1000) c=1000; if (c<50) c=50; printf "%d", c }')"
    echo "[INFO] Ejecutando nping TCP SYN hacia ${TARGET}:${PORT}..."
    run_to_file "$outfile" nping --tcp -p "$PORT" --rate 5 -c "$count" "$TARGET" || true
  elif have hping3; then
    local outfile="${RAW_DIR}/hping3_tcp_${TARGET}_${PORT}.log"
    local count
    count="$(awk -v d="$DURATION" 'BEGIN { c=d*5; if (c>1000) c=1000; if (c<50) c=50; printf "%d", c }')"
    echo "[INFO] Ejecutando hping3 TCP SYN hacia ${TARGET}:${PORT}..."
    run_to_file "$outfile" hping3 -S -p "$PORT" -c "$count" -i u200000 "$TARGET" || true
  else
    echo "nping/hping3 no instalados; omitiendo RTT TCP SYN." >> "$NOTES"
  fi
}

run_iperf_test() {
  [ -n "$IPERF_SERVER" ] || return 0

  if ! have iperf3; then
    echo "iperf3 no instalado; se especifico --iperf-server pero no se pudo ejecutar." >> "$NOTES"
    return 0
  fi

  echo "[INFO] Ejecutando iperf3 TCP y UDP contra ${IPERF_SERVER}..."

  run_timeout_to_file "$((DURATION + 10))" "${RAW_DIR}/iperf3_tcp.json" \
    iperf3 -c "$IPERF_SERVER" -t "$DURATION" -i "$INTERVAL" -J || true

  # Para SCADA conviene probar bajo ancho de banda controlado, no saturar por defecto.
  run_timeout_to_file "$((DURATION + 10))" "${RAW_DIR}/iperf3_udp_1M.json" \
    iperf3 -c "$IPERF_SERVER" -u -b 1M -t "$DURATION" -i "$INTERVAL" -J || true
}

run_openssl_speed() {
  [ "$ENABLE_OPENSSL" = "1" ] || return 0
  if ! have openssl; then
    echo "openssl no instalado; omitiendo benchmark criptografico local." >> "$NOTES"
    return 0
  fi

  echo "[INFO] Ejecutando openssl speed corto..."
  run_to_file "${RAW_DIR}/openssl_speed_aes_128_gcm.log" openssl speed -seconds 3 -evp aes-128-gcm || true
  run_to_file "${RAW_DIR}/openssl_speed_aes_256_gcm.log" openssl speed -seconds 3 -evp aes-256-gcm || true
  run_to_file "${RAW_DIR}/openssl_speed_chacha20_poly1305.log" openssl speed -seconds 3 -evp chacha20-poly1305 || true
}

run_vpn_specific_status() {
  if have wg; then
    run_to_file "${RAW_DIR}/wireguard_show.log" wg show || true
  fi
  if have ipsec; then
    run_to_file "${RAW_DIR}/ipsec_status.log" ipsec statusall || true
  fi
  if have strongswan; then
    run_to_file "${RAW_DIR}/strongswan_status.log" strongswan statusall || true
  fi
  if have systemctl; then
    systemctl is-active --quiet openvpn && run_to_file "${RAW_DIR}/openvpn_systemctl_status.log" systemctl status openvpn --no-pager || true
  fi
}

entropy_from_pcap() {
  if [ "$ENABLE_CAPTURE" != "1" ]; then
    return 0
  fi

  if ! have tshark; then
    echo "tshark no disponible para extraer payload y estimar entropia." >> "$NOTES"
    return 0
  fi

  local hexfile="${RAW_DIR}/tcp_payload_${PORT}.hex"
  local binfile="${RAW_DIR}/tcp_payload_${PORT}.bin"
  local stringsfile="${RAW_DIR}/tcp_payload_strings.txt"

  : > "$hexfile"
  if [ ! -s "${OUT_DIR}/pcap_file.txt" ]; then
    echo "No hay pcap disponible para entropia." >> "$NOTES"
    return 0
  fi

  echo "[INFO] Extrayendo payload TCP de puerto ${PORT} para entropía aproximada..."
  while IFS= read -r pcap; do
    [ -n "$pcap" ] && [ -f "$pcap" ] || continue
    log_cmd "tshark -r $pcap -Y tcp.port==$PORT -T fields -e tcp.payload >> $hexfile"
    tshark -r "$pcap" -Y "tcp.port==$PORT" -T fields -e tcp.payload >> "$hexfile" 2>>"${RAW_DIR}/entropy_extract.log" || true
  done < "${OUT_DIR}/pcap_file.txt"

  # Wireshark entrega hex con ':' por byte. Se normaliza.
  tr -d ':\n\r\t ' < "$hexfile" | xxd -r -p > "$binfile" 2>>"${RAW_DIR}/entropy_extract.log" || true

  if [ -s "$binfile" ]; then
    strings -a "$binfile" > "$stringsfile" 2>/dev/null || true

    if have ent; then
      run_to_file "${RAW_DIR}/entropy_ent.log" ent "$binfile" || true
    fi

    if have python3; then
      local entropy_csv="${CSV_DIR}/payload_entropy.csv"
      python3 - "$binfile" "$entropy_csv" <<'PY'
import collections
import csv
import math
import sys

path = sys.argv[1]
out = sys.argv[2]
data = open(path, "rb").read()
n = len(data)
if n == 0:
    entropy = 0.0
else:
    counts = collections.Counter(data)
    entropy = -sum((c/n) * math.log2(c/n) for c in counts.values())

print(f"payload_bytes={n}")
print(f"shannon_entropy_bits_per_byte={entropy:.6f}")

with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["metric", "value", "unit"])
    w.writerow(["payload_bytes", n, "bytes"])
    w.writerow(["shannon_entropy", f"{entropy:.6f}", "bits_per_byte"])
PY
      local entropy_value payload_bytes
      entropy_value="$(awk -F, '$1=="shannon_entropy"{print $2}' "$entropy_csv" 2>/dev/null | tr -d '"')"
      payload_bytes="$(awk -F, '$1=="payload_bytes"{print $2}' "$entropy_csv" 2>/dev/null | tr -d '"')"
      [ -n "$entropy_value" ] && add_metric "payload_entropy" "$entropy_value" "bits_per_byte" "csv/payload_entropy.csv" "Calculada sobre tcp.payload del puerto especificado en la interfaz capturada."
      [ -n "$payload_bytes" ] && add_metric "payload_bytes_for_entropy" "$payload_bytes" "bytes" "csv/payload_entropy.csv" "Cantidad de bytes usados para entropia."
    fi
  else
    echo "No se extrajo payload TCP para puerto $PORT. Si mide VPN cifrada en interfaz fisica, use el puerto del tunel o capture la interfaz correcta." >> "$NOTES"
  fi
}

parse_results() {
  echo "[INFO] Generando resumen CSV..."

  # Ping: packet loss y rtt min/avg/max/mdev.
  local pinglog="${RAW_DIR}/ping_${TARGET}.log"
  if [ -f "$pinglog" ]; then
    local loss
    loss="$(grep -Eo '[0-9]+(\.[0-9]+)?% packet loss' "$pinglog" | tail -n 1 | awk '{print $1}' | tr -d '%')"
    [ -n "$loss" ] && add_metric "icmp_packet_loss" "$loss" "%" "raw/$(basename "$pinglog")" ""

    local rtt_line
    rtt_line="$(grep -E '^(rtt|round-trip) ' "$pinglog" | tail -n 1)"
    if [ -n "$rtt_line" ]; then
      local vals
      vals="$(echo "$rtt_line" | awk -F'= ' '{print $2}' | awk '{print $1}')"
      local rtt_min rtt_avg rtt_max rtt_mdev
      rtt_min="$(echo "$vals" | awk -F/ '{print $1}')"
      rtt_avg="$(echo "$vals" | awk -F/ '{print $2}')"
      rtt_max="$(echo "$vals" | awk -F/ '{print $3}')"
      rtt_mdev="$(echo "$vals" | awk -F/ '{print $4}')"
      [ -n "$rtt_min" ] && add_metric "icmp_rtt_min" "$rtt_min" "ms" "raw/$(basename "$pinglog")" ""
      [ -n "$rtt_avg" ] && add_metric "icmp_rtt_avg" "$rtt_avg" "ms" "raw/$(basename "$pinglog")" ""
      [ -n "$rtt_max" ] && add_metric "icmp_rtt_max" "$rtt_max" "ms" "raw/$(basename "$pinglog")" ""
      [ -n "$rtt_mdev" ] && add_metric "icmp_rtt_mdev" "$rtt_mdev" "ms" "raw/$(basename "$pinglog")" "Proxy simple de jitter ICMP."
    fi
  fi

  # TCP connect CSV.
  local tcp_csv="${CSV_DIR}/tcp_connect_${TARGET}_${PORT}.csv"
  if [ -f "$tcp_csv" ] && have python3; then
    local stats_csv="${CSV_DIR}/tcp_connect_stats.csv"
    python3 - "$tcp_csv" "$stats_csv" <<'PY'
import csv
import statistics
import sys

src, dst = sys.argv[1], sys.argv[2]
values = []
oks = 0
total = 0
with open(src, newline="") as f:
    for row in csv.DictReader(f):
        total += 1
        if row.get("ok") == "1":
            oks += 1
            values.append(float(row["tcp_connect_ms"]))

def percentile(vals, p):
    if not vals:
        return ""
    vals = sorted(vals)
    k = (len(vals) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    if f == c:
        return vals[f]
    return vals[f] + (vals[c] - vals[f]) * (k - f)

rows = []
rows.append(("tcp_connect_success_rate", oks / total * 100 if total else 0, "%"))
rows.append(("tcp_connect_samples", total, "samples"))
if values:
    rows += [
        ("tcp_connect_min", min(values), "ms"),
        ("tcp_connect_avg", statistics.mean(values), "ms"),
        ("tcp_connect_median", statistics.median(values), "ms"),
        ("tcp_connect_p95", percentile(values, 95), "ms"),
        ("tcp_connect_p99", percentile(values, 99), "ms"),
        ("tcp_connect_max", max(values), "ms"),
    ]

with open(dst, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["metric", "value", "unit"])
    for m, v, u in rows:
        if isinstance(v, float):
            v = f"{v:.6f}"
        w.writerow([m, v, u])
PY
    while IFS=, read -r metric value unit; do
      [ "$metric" = "metric" ] && continue
      add_metric "$metric" "$value" "$unit" "csv/tcp_connect_stats.csv" "Latencia de establecimiento TCP hacia el puerto de servicio."
    done < "$stats_csv"
  fi

  # capinfos si existe.
  if [ -s "${OUT_DIR}/pcap_file.txt" ] && have capinfos; then
    : > "${RAW_DIR}/capinfos.log"
    while IFS= read -r pcap; do
      [ -n "$pcap" ] && [ -f "$pcap" ] || continue
      echo "### $pcap" >> "${RAW_DIR}/capinfos.log"
      capinfos "$pcap" >> "${RAW_DIR}/capinfos.log" 2>&1 || true
      echo >> "${RAW_DIR}/capinfos.log"
    done < "${OUT_DIR}/pcap_file.txt"
  fi

  # iperf3 JSON parsing simple.
  if [ -f "${RAW_DIR}/iperf3_tcp.json" ] && have python3; then
    python3 - "${RAW_DIR}/iperf3_tcp.json" "${CSV_DIR}/iperf3_tcp_summary.csv" <<'PY' || true
import csv, json, sys
j = json.load(open(sys.argv[1]))
end = j.get("end", {})
s = end.get("sum_received") or end.get("sum") or {}
rows = [
    ("iperf3_tcp_bits_per_second", s.get("bits_per_second", ""), "bps"),
    ("iperf3_tcp_retransmits", (end.get("sum_sent") or {}).get("retransmits", ""), "count"),
]
with open(sys.argv[2], "w", newline="") as f:
    w=csv.writer(f); w.writerow(["metric","value","unit"]); w.writerows(rows)
PY
    if [ -f "${CSV_DIR}/iperf3_tcp_summary.csv" ]; then
      while IFS=, read -r metric value unit; do
        [ "$metric" = "metric" ] && continue
        [ -n "$value" ] && add_metric "$metric" "$value" "$unit" "csv/iperf3_tcp_summary.csv" ""
      done < "${CSV_DIR}/iperf3_tcp_summary.csv"
    fi
  fi

  if [ -f "${RAW_DIR}/iperf3_udp_1M.json" ] && have python3; then
    python3 - "${RAW_DIR}/iperf3_udp_1M.json" "${CSV_DIR}/iperf3_udp_summary.csv" <<'PY' || true
import csv, json, sys
j = json.load(open(sys.argv[1]))
end = j.get("end", {})
s = end.get("sum") or {}
rows = [
    ("iperf3_udp_bits_per_second", s.get("bits_per_second", ""), "bps"),
    ("iperf3_udp_jitter_ms", s.get("jitter_ms", ""), "ms"),
    ("iperf3_udp_lost_percent", s.get("lost_percent", ""), "%"),
    ("iperf3_udp_lost_packets", s.get("lost_packets", ""), "packets"),
]
with open(sys.argv[2], "w", newline="") as f:
    w=csv.writer(f); w.writerow(["metric","value","unit"]); w.writerows(rows)
PY
    if [ -f "${CSV_DIR}/iperf3_udp_summary.csv" ]; then
      while IFS=, read -r metric value unit; do
        [ "$metric" = "metric" ] && continue
        [ -n "$value" ] && add_metric "$metric" "$value" "$unit" "csv/iperf3_udp_summary.csv" ""
      done < "${CSV_DIR}/iperf3_udp_summary.csv"
    fi
  fi
}


write_consolidated_outputs() {
  if ! have python3; then
    echo "python3 no instalado; no se pudo generar CSV consolidado ni reporte HTML." >> "$NOTES"
    return 0
  fi

  echo "[INFO] Generando CSV consolidado, metricas interpretadas y graficos HTML..."
  python3 - "$OUT_DIR" "$RAW_DIR" "$CSV_DIR" "$PCAP_DIR" "$LABEL" "$TARGET" "$PORT" "$IFACE_SPEC" "$DURATION" "$INTERVAL" "$START_STAMP" "$RUN_ID" "$VERSION" <<'PYREPORT'
import csv
import glob
import html
import math
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

out_dir, raw_dir, csv_dir, pcap_dir, label, target, port, iface, duration, interval, start_stamp, run_id, version = sys.argv[1:14]
iface_list = [x for x in re.split(r"[,\s]+", iface.strip()) if x]
if not iface_list and iface:
    iface_list = [iface]
primary_iface = iface_list[0] if iface_list else iface

def iface_metric_suffix(iface_name):
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(iface_name))
    return "__" + safe if len(iface_list) > 1 else ""

summary_path = os.path.join(csv_dir, "summary.csv")
dataset_csv = os.path.join(csv_dir, "probe_dataset.csv")
interpretation_csv = os.path.join(csv_dir, "probe_interpretation.csv")
packet_counts_csv = os.path.join(csv_dir, "packet_service_counts.csv")
latency_samples_csv = os.path.join(csv_dir, "latency_samples.csv")
latency_stats_csv = os.path.join(csv_dir, "latency_stats.csv")
cpu_process_csv = os.path.join(csv_dir, "cpu_process_summary.csv")
interface_delta_csv = os.path.join(csv_dir, "interface_delta.csv")
key_metrics_csv = os.path.join(csv_dir, "key_metrics_compact.csv")
network_rates_csv = os.path.join(csv_dir, "network_rates.csv")
pmtu_loss_csv = os.path.join(csv_dir, "pmtu_loss_summary.csv")
tcp_health_csv = os.path.join(csv_dir, "tcp_health_summary.csv")
crypto_speed_csv = os.path.join(csv_dir, "openssl_speed_summary.csv")
html_report = os.path.join(out_dir, "probe_report.html")

DATASET_FIELDS = [
    "run_id", "scenario", "target", "port", "iface", "duration_seconds",
    "interval_seconds", "start_stamp", "record_type", "service", "timestamp", "sample",
    "metric", "value", "unit", "ok", "status", "source_file", "notes"
]

INTERPRETATION_FIELDS = [
    "run_id", "scenario", "target", "iface", "section", "item", "metric",
    "value", "unit", "status", "interpretation", "recommendation"
]

PACKET_FIELDS = [
    "run_id", "scenario", "target", "iface", "source_method", "service", "direction",
    "packets", "bytes", "notes"
]

LATENCY_SAMPLE_FIELDS = [
    "run_id", "scenario", "target", "iface", "service", "sample", "timestamp",
    "value_ms", "ok", "source_file", "notes"
]

LATENCY_STATS_FIELDS = [
    "run_id", "scenario", "target", "iface", "service", "n", "min_ms", "q1_ms",
    "median_ms", "mean_ms", "q3_ms", "p95_ms", "p99_ms", "max_ms", "std_ms",
    "ci95_low_ms", "ci95_high_ms", "source_file"
]

CPU_FIELDS = [
    "run_id", "scenario", "target", "iface", "rank", "process", "avg_cpu_pct",
    "cumulative_cpu_pct", "samples", "source_file"
]

IFACE_FIELDS = [
    "run_id", "scenario", "target", "iface", "rx_packets_delta", "tx_packets_delta",
    "rx_bytes_delta", "tx_bytes_delta", "source_file"
]

KEY_FIELDS = [
    "run_id", "scenario", "target", "iface", "metric", "label", "value", "unit",
    "source_file", "notes"
]

SIMPLE_METRIC_FIELDS = [
    "run_id", "scenario", "target", "iface", "metric", "label", "value", "unit",
    "source_file", "notes"
]

CRYPTO_FIELDS = [
    "run_id", "scenario", "target", "iface", "algorithm", "throughput_kBps",
    "source_file", "notes"
]

METRIC_LABELS = {
    "icmp_packet_loss": "Perdida ICMP",
    "icmp_rtt_min": "RTT ICMP minimo",
    "icmp_rtt_avg": "RTT ICMP promedio",
    "icmp_rtt_max": "RTT ICMP maximo",
    "icmp_rtt_mdev": "Variacion ICMP",
    "tcp_connect_success_rate": "Exito TCP connect",
    "tcp_connect_samples": "Muestras TCP connect",
    "tcp_connect_min": "TCP connect minimo",
    "tcp_connect_avg": "TCP connect promedio",
    "tcp_connect_median": "TCP connect mediana",
    "tcp_connect_p95": "TCP connect p95",
    "tcp_connect_p99": "TCP connect p99",
    "tcp_connect_max": "TCP connect maximo",
    "pmtu_payload_max_success": "Payload ICMP maximo sin fragmentar",
    "pmtu_ipv4_approx": "PMTU IPv4 aproximada",
    "payload_entropy": "Entropia de payload",
    "payload_bytes_for_entropy": "Bytes usados para entropia",
    "iperf3_tcp_bits_per_second": "Throughput TCP iperf3",
    "iperf3_tcp_retransmits": "Retransmisiones TCP iperf3",
    "iperf3_udp_bits_per_second": "Throughput UDP iperf3",
    "iperf3_udp_jitter_ms": "Jitter UDP iperf3",
    "iperf3_udp_lost_percent": "Perdida UDP iperf3",
    "iperf3_udp_lost_packets": "Paquetes UDP perdidos",
    "cpu_avg_user_pct": "CPU usuario promedio",
    "cpu_avg_system_pct": "CPU sistema promedio",
    "cpu_avg_busy_pct": "CPU ocupada promedio",
    "cpu_avg_idle_pct": "CPU libre promedio",
    "cpu_avg_iowait_pct": "CPU iowait promedio",
    "net_rx_kBps": "Recepcion promedio",
    "net_tx_kBps": "Transmision promedio",
    "net_ifutil_pct": "Utilizacion de interfaz",
    "nping_tcp_avg_rtt_ms": "RTT TCP SYN promedio",
    "nping_tcp_min_rtt_ms": "RTT TCP SYN minimo",
    "nping_tcp_max_rtt_ms": "RTT TCP SYN maximo",
    "interface_tx_packets_delta": "Paquetes TX interfaz",
    "interface_rx_packets_delta": "Paquetes RX interfaz",
    "interface_tx_bytes_delta": "Bytes TX interfaz",
    "interface_rx_bytes_delta": "Bytes RX interfaz",
}


def rel(path):
    try:
        return os.path.relpath(path, out_dir)
    except Exception:
        return path


def esc(x):
    return html.escape(str(x if x is not None else ""))


def to_float(value):
    try:
        if value is None or value == "":
            return None
        text = str(value).strip().replace("%", "")
        # sysstat/pidstat en sistemas con locale espanol usan coma decimal: 2,52.
        # Si hay coma, se asume formato decimal latino y se eliminan puntos de miles.
        if "," in text:
            text = text.replace(".", "").replace(",", ".")
        return float(text)
    except Exception:
        return None


def fmt(value, decimals=3):
    if value is None or value == "":
        return ""
    try:
        f = float(value)
    except Exception:
        return str(value)
    if abs(f) >= 1000000:
        return f"{f:.2e}"
    if abs(f) >= 100:
        return f"{f:.2f}"
    return f"{f:.{decimals}f}"


def write_csv(path, fields, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def read_csv_dicts(path):
    if not os.path.isfile(path):
        return []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def dataset_row(record_type, metric="", value="", unit="", service="", timestamp="", sample="", ok="", status="", source_file="", notes=""):
    return {
        "run_id": run_id,
        "scenario": label,
        "target": target,
        "port": port,
        "iface": iface,
        "duration_seconds": duration,
        "interval_seconds": interval,
        "start_stamp": start_stamp,
        "record_type": record_type,
        "service": service,
        "timestamp": timestamp,
        "sample": sample,
        "metric": metric,
        "value": value,
        "unit": unit,
        "ok": ok,
        "status": status,
        "source_file": source_file,
        "notes": notes,
    }


def metric_map(rows):
    out = {}
    for row in rows:
        if row.get("record_type") == "metric":
            out[row.get("metric", "")] = row
    return out


def add_metric(rows, metric, value, unit, source_file, notes=""):
    if value is None or value == "":
        return
    rows.append(dataset_row("metric", metric=metric, value=fmt(value), unit=unit, source_file=source_file, notes=notes))


def parse_summary_metrics():
    rows = []
    for row in read_csv_dicts(summary_path):
        rows.append(dataset_row(
            "metric",
            metric=row.get("metric", ""),
            value=row.get("value", ""),
            unit=row.get("unit", ""),
            source_file=row.get("source_file", ""),
            notes=row.get("notes", ""),
        ))
    return rows


def parse_tcp_connect_samples():
    dataset = []
    samples = []
    for path in sorted(glob.glob(os.path.join(csv_dir, f"tcp_connect_{target}_{port}.csv"))):
        if os.path.basename(path) == "tcp_connect_stats.csv":
            continue
        for row in read_csv_dicts(path):
            ok = row.get("ok", "")
            status = "OK" if ok == "1" else "ERROR"
            v = row.get("tcp_connect_ms", "")
            dataset.append(dataset_row(
                "latency_sample", service="TCP_CONNECT", timestamp=row.get("epoch", ""), sample=row.get("sample", ""),
                metric="tcp_connect_ms", value=v, unit="ms", ok=ok, status=status,
                source_file=rel(path), notes=row.get("error", "")
            ))
            if to_float(v) is not None:
                samples.append({
                    "run_id": run_id, "scenario": label, "target": target, "iface": iface,
                    "service": "TCP_CONNECT", "sample": row.get("sample", ""), "timestamp": row.get("epoch", ""),
                    "value_ms": v, "ok": ok, "source_file": rel(path), "notes": row.get("error", "")
                })
    return dataset, samples


def parse_icmp_ping_samples():
    dataset = []
    samples = []
    path = os.path.join(raw_dir, f"ping_{target}.log")
    if not os.path.isfile(path):
        return dataset, samples
    pat = re.compile(r"^(?:\[(?P<ts>[0-9.]+)\]\s*)?.*icmp_seq=(?P<seq>\d+).*time=(?P<time>[0-9.]+)\s*ms")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pat.search(line)
                if not m:
                    continue
                row = {
                    "run_id": run_id, "scenario": label, "target": target, "iface": iface,
                    "service": "ICMP", "sample": m.group("seq"), "timestamp": m.group("ts") or "",
                    "value_ms": m.group("time"), "ok": "1", "source_file": rel(path),
                    "notes": "muestra ICMP echo reply"
                }
                samples.append(row)
                dataset.append(dataset_row(
                    "latency_sample", service="ICMP", timestamp=row["timestamp"], sample=row["sample"],
                    metric="icmp_rtt_ms", value=row["value_ms"], unit="ms", ok="1", status="OK",
                    source_file=row["source_file"], notes=row["notes"]
                ))
    except Exception:
        pass
    return dataset, samples


def parse_ping_count():
    path = os.path.join(raw_dir, f"ping_{target}.log")
    if not os.path.isfile(path):
        return None, None
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return None, None
    m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received", text)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None, None


def percentile(vals, p):
    vals = sorted(v for v in vals if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    k = (len(vals) - 1) * p / 100.0
    f = int(math.floor(k))
    c = min(f + 1, len(vals) - 1)
    if f == c:
        return vals[f]
    return vals[f] + (vals[c] - vals[f]) * (k - f)


def build_latency_stats(samples):
    by = {}
    sources = {}
    for row in samples:
        service = row.get("service", "UNKNOWN")
        v = to_float(row.get("value_ms"))
        if v is None:
            continue
        by.setdefault(service, []).append(v)
        sources.setdefault(service, row.get("source_file", ""))
    stats_rows = []
    for service, vals in sorted(by.items()):
        n = len(vals)
        mean = statistics.mean(vals) if vals else None
        std = statistics.stdev(vals) if len(vals) > 1 else 0.0
        margin = 1.96 * std / math.sqrt(n) if n > 1 else 0.0
        stats_rows.append({
            "run_id": run_id, "scenario": label, "target": target, "iface": iface,
            "service": service, "n": n,
            "min_ms": fmt(min(vals)), "q1_ms": fmt(percentile(vals, 25)),
            "median_ms": fmt(statistics.median(vals)), "mean_ms": fmt(mean),
            "q3_ms": fmt(percentile(vals, 75)), "p95_ms": fmt(percentile(vals, 95)),
            "p99_ms": fmt(percentile(vals, 99)), "max_ms": fmt(max(vals)),
            "std_ms": fmt(std), "ci95_low_ms": fmt(mean - margin if mean is not None else None),
            "ci95_high_ms": fmt(mean + margin if mean is not None else None),
            "source_file": sources.get(service, ""),
        })
    return stats_rows


def run_tshark_packet_counts():
    pcap_txt = os.path.join(out_dir, "pcap_file.txt")
    if not os.path.isfile(pcap_txt):
        return []
    try:
        pcaps = [p.strip() for p in open(pcap_txt, encoding="utf-8", errors="replace").read().splitlines() if p.strip()]
    except Exception:
        return []
    pcaps = [p for p in pcaps if os.path.isfile(p)]
    if not pcaps:
        return []
    counts = {}
    for pcap in pcaps:
        try:
            cmd = [
                "tshark", "-r", pcap,
                "-Y", f"ip.addr == {target}",
                "-T", "fields",
                "-e", "frame.len", "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "icmp.type"
            ]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30)
        except Exception:
            continue
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            while len(parts) < 9:
                parts.append("")
            frame_len, ip_src, ip_dst, ip_proto, tcp_sport, tcp_dport, udp_sport, udp_dport, icmp_type = parts[:9]
            size = int(to_float(frame_len) or 0)
            if ip_dst == target:
                direction = "sent_to_target"
            elif ip_src == target:
                direction = "received_from_target"
            else:
                direction = "other"
            service = "OTHER"
            if ip_proto == "1":
                service = "ICMP"
            elif ip_proto == "6" and (tcp_sport == port or tcp_dport == port):
                service = "TCP_PORT_" + str(port)
            elif ip_proto == "17" and (udp_sport == port or udp_dport == port):
                service = "UDP_PORT_" + str(port)
            elif ip_proto == "6":
                service = "TCP_OTHER"
            elif ip_proto == "17":
                service = "UDP_OTHER"
            key = (service, direction)
            if key not in counts:
                counts[key] = {"packets": 0, "bytes": 0}
            counts[key]["packets"] += 1
            counts[key]["bytes"] += size
    rows = []
    for (service, direction), c in sorted(counts.items()):
        rows.append({
            "run_id": run_id, "scenario": label, "target": target, "iface": iface,
            "source_method": "pcap_tshark", "service": service, "direction": direction,
            "packets": c["packets"], "bytes": c["bytes"],
            "notes": "Conteo real desde pcap; TCP_PORT agrupa conexiones TCP al puerto objetivo."
        })
    return rows

def estimated_packet_counts(latency_samples):
    rows = []
    tx, rx = parse_ping_count()
    if tx is not None:
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "ICMP", "direction": "sent_to_target", "packets": tx, "bytes": "", "notes": "Estimado desde resumen de ping."})
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "ICMP", "direction": "received_from_target", "packets": rx or 0, "bytes": "", "notes": "Estimado desde resumen de ping."})
    tcp_samples = [r for r in latency_samples if r.get("service") == "TCP_CONNECT"]
    if tcp_samples:
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "TCP_CONNECT", "direction": "connection_attempts", "packets": len(tcp_samples), "bytes": "", "notes": "No es conteo de paquetes de red; es numero de intentos TCP connect."})
    mtr_log = os.path.join(raw_dir, f"mtr_{target}.log")
    if os.path.isfile(mtr_log):
        try:
            text = open(mtr_log, encoding="utf-8", errors="replace").read()
            m = re.search(r"\b(\d+)\s+packets", text, flags=re.I)
            count = int(m.group(1)) if m else min(int(duration or 0), 100)
        except Exception:
            count = ""
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "MTR", "direction": "probe_cycles", "packets": count, "bytes": "", "notes": "Estimacion de ciclos MTR; puede usar ICMP/UDP segun implementacion."})
    nping_log = os.path.join(raw_dir, f"nping_tcp_{target}_{port}.log")
    if os.path.isfile(nping_log):
        try:
            text = open(nping_log, encoding="utf-8", errors="replace").read()
            m = re.search(r"Raw packets sent:\s*(\d+)", text, flags=re.I)
            count = int(m.group(1)) if m else ""
        except Exception:
            count = ""
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "NPING_TCP_SYN", "direction": "sent_to_target", "packets": count, "bytes": "", "notes": "Estimado desde nping TCP SYN."})
    hping_log = os.path.join(raw_dir, f"hping3_tcp_{target}_{port}.log")
    if os.path.isfile(hping_log):
        try:
            text = open(hping_log, encoding="utf-8", errors="replace").read()
            m = re.search(r"(\d+)\s+packets transmitted", text, flags=re.I)
            count = int(m.group(1)) if m else ""
        except Exception:
            count = ""
        rows.append({"run_id": run_id, "scenario": label, "target": target, "iface": iface, "source_method": "estimated_from_logs", "service": "HPING3_TCP_SYN", "direction": "sent_to_target", "packets": count, "bytes": "", "notes": "Estimado desde hping3."})
    return rows


def parse_interface_counters(path):
    if not os.path.isfile(path):
        return None
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return None
    rx_bytes = rx_packets = tx_bytes = tx_packets = None
    for i, line in enumerate(lines):
        if line.strip().startswith("RX:") and i + 2 < len(lines):
            nums = lines[i + 2].split()
            if len(nums) >= 2:
                rx_bytes = int(to_float(nums[0]) or 0)
                rx_packets = int(to_float(nums[1]) or 0)
        if line.strip().startswith("TX:") and i + 2 < len(lines):
            nums = lines[i + 2].split()
            if len(nums) >= 2:
                tx_bytes = int(to_float(nums[0]) or 0)
                tx_packets = int(to_float(nums[1]) or 0)
    if rx_bytes is None and tx_bytes is None:
        return None
    return {"rx_bytes": rx_bytes or 0, "rx_packets": rx_packets or 0, "tx_bytes": tx_bytes or 0, "tx_packets": tx_packets or 0}


def sar_interface_estimate_delta(iface_name):
    """Fallback: estima delta de interfaz desde sar cuando los snapshots before/after no existen."""
    path = os.path.join(raw_dir, "sar_net_dev.log")
    if not os.path.isfile(path):
        return None
    header = None
    samples = []
    avg_tokens = ("Average:", "Media:", "Promedio:")
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            parts = line.split()
            if not parts:
                continue
            if "IFACE" in parts and "rxpck/s" in parts:
                header = parts
                continue
            if not header or len(parts) < 3:
                continue
            if parts[1] != iface_name:
                continue
            if parts[0] in avg_tokens or re.match(r"^\d{1,2}:\d{2}:\d{2}$", parts[0]):
                samples.append(parts)
        if not header or not samples:
            return None
        # Si existe una fila Media/Average para la interfaz, se usa solo esa; si no, se promedian muestras.
        avg_rows = [p for p in samples if p[0] in avg_tokens]
        use_rows = avg_rows or samples
        def val_for(key):
            if key not in header:
                return 0.0
            vi = header.index(key)
            vals = [to_float(row[vi]) for row in use_rows if vi < len(row) and to_float(row[vi]) is not None]
            return statistics.mean(vals) if vals else 0.0
        dur = to_float(duration) or 0.0
        return {
            "rx_packets": val_for("rxpck/s") * dur,
            "tx_packets": val_for("txpck/s") * dur,
            "rx_bytes": val_for("rxkB/s") * 1024.0 * dur,
            "tx_bytes": val_for("txkB/s") * 1024.0 * dur,
            "source_file": "raw/sar_net_dev.log",
            "estimated": True,
        }
    except Exception:
        return None


def parse_interface_delta():
    rows = []
    for iface_name in iface_list:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", iface_name)
        before = parse_interface_counters(os.path.join(raw_dir, f"ip_s_link_before_{iface_name}.log"))
        after = parse_interface_counters(os.path.join(raw_dir, f"ip_s_link_after_{iface_name}.log"))
        if before and after:
            rows.append({
                "run_id": run_id, "scenario": label, "target": target, "iface": iface_name,
                "rx_packets_delta": max(0, after["rx_packets"] - before["rx_packets"]),
                "tx_packets_delta": max(0, after["tx_packets"] - before["tx_packets"]),
                "rx_bytes_delta": max(0, after["rx_bytes"] - before["rx_bytes"]),
                "tx_bytes_delta": max(0, after["tx_bytes"] - before["tx_bytes"]),
                "source_file": f"raw/ip_s_link_before_{iface_name}.log;raw/ip_s_link_after_{iface_name}.log",
            })
        else:
            est = sar_interface_estimate_delta(iface_name)
            if est:
                rows.append({
                    "run_id": run_id, "scenario": label, "target": target, "iface": iface_name,
                    "rx_packets_delta": int(round(est["rx_packets"])),
                    "tx_packets_delta": int(round(est["tx_packets"])),
                    "rx_bytes_delta": int(round(est["rx_bytes"])),
                    "tx_bytes_delta": int(round(est["tx_bytes"])),
                    "source_file": est["source_file"] + " (estimado desde tasas promedio)",
                })
    if rows:
        return rows
    # Compatibilidad con corridas antiguas de una sola interfaz.
    before = parse_interface_counters(os.path.join(raw_dir, "ip_s_link_before.log"))
    after = parse_interface_counters(os.path.join(raw_dir, "ip_s_link_after.log"))
    if before and after:
        return [{
            "run_id": run_id, "scenario": label, "target": target, "iface": primary_iface,
            "rx_packets_delta": max(0, after["rx_packets"] - before["rx_packets"]),
            "tx_packets_delta": max(0, after["tx_packets"] - before["tx_packets"]),
            "rx_bytes_delta": max(0, after["rx_bytes"] - before["rx_bytes"]),
            "tx_bytes_delta": max(0, after["tx_bytes"] - before["tx_bytes"]),
            "source_file": "raw/ip_s_link_before.log;raw/ip_s_link_after.log",
        }]
    return []

def parse_sar_cpu(rows):
    path = os.path.join(raw_dir, "sar_cpu.log")
    if not os.path.isfile(path):
        return
    header = None
    samples = []
    avg_tokens = ("Average:", "Media:", "Promedio:")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                if "CPU" in parts and "%idle" in parts:
                    header = parts
                    continue
                if not header or len(parts) < 3:
                    continue
                if parts[1] != "all":
                    continue
                if parts[0] in avg_tokens or re.match(r"^\d{1,2}:\d{2}:\d{2}$", parts[0]):
                    samples.append(parts)
        if not header or not samples:
            return
        avg_rows = [p for p in samples if p[0] in avg_tokens]
        use_rows = avg_rows or samples
        def val_for(*keys):
            for key in keys:
                if key in header:
                    vi = header.index(key)
                    vals = [to_float(row[vi]) for row in use_rows if vi < len(row) and to_float(row[vi]) is not None]
                    return statistics.mean(vals) if vals else None
            return None
        idle = val_for("%idle")
        add_metric(rows, "cpu_avg_user_pct", val_for("%user", "%usr"), "%", "raw/sar_cpu.log", "Promedio de sar -u ALL para CPU all.")
        add_metric(rows, "cpu_avg_system_pct", val_for("%system", "%sys"), "%", "raw/sar_cpu.log", "Promedio de sar -u ALL para CPU all.")
        add_metric(rows, "cpu_avg_iowait_pct", val_for("%iowait"), "%", "raw/sar_cpu.log", "Promedio de sar -u ALL para CPU all.")
        add_metric(rows, "cpu_avg_idle_pct", idle, "%", "raw/sar_cpu.log", "Promedio de sar -u ALL para CPU all.")
        if idle is not None:
            add_metric(rows, "cpu_avg_busy_pct", max(0.0, 100.0 - idle), "%", "raw/sar_cpu.log", "Calculado como 100 - %idle promedio.")
    except Exception:
        return


def parse_sar_net(rows):
    path = os.path.join(raw_dir, "sar_net_dev.log")
    if not os.path.isfile(path):
        return
    for iface_name in iface_list:
        header = None
        samples = []
        avg_tokens = ("Average:", "Media:", "Promedio:")
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if not parts:
                        continue
                    if "IFACE" in parts and ("rxkB/s" in parts or "rxpck/s" in parts):
                        header = parts
                        continue
                    if not header or len(parts) < 3:
                        continue
                    if parts[1] != iface_name:
                        continue
                    if parts[0] in avg_tokens or re.match(r"^\d{1,2}:\d{2}:\d{2}$", parts[0]):
                        samples.append(parts)
            if not header or not samples:
                continue
            avg_rows = [p for p in samples if p[0] in avg_tokens]
            use_rows = avg_rows or samples
            def val_for(key):
                if key not in header:
                    return None
                vi = header.index(key)
                vals = [to_float(row[vi]) for row in use_rows if vi < len(row) and to_float(row[vi]) is not None]
                return statistics.mean(vals) if vals else None
            suffix = iface_metric_suffix(iface_name)
            note = f"Promedio sar -n DEV para {iface_name}."
            add_metric(rows, "net_rx_kBps" + suffix, val_for("rxkB/s"), "kB/s", "raw/sar_net_dev.log", note)
            add_metric(rows, "net_tx_kBps" + suffix, val_for("txkB/s"), "kB/s", "raw/sar_net_dev.log", note)
            add_metric(rows, "net_rxpck_s" + suffix, val_for("rxpck/s"), "packets/s", "raw/sar_net_dev.log", note)
            add_metric(rows, "net_txpck_s" + suffix, val_for("txpck/s"), "packets/s", "raw/sar_net_dev.log", note)
            add_metric(rows, "net_ifutil_pct" + suffix, val_for("%ifutil"), "%", "raw/sar_net_dev.log", f"Promedio de utilizacion de interfaz para {iface_name}.")
        except Exception:
            continue

def parse_nping(rows):
    for path in sorted(glob.glob(os.path.join(raw_dir, f"nping_tcp_{target}_{port}.log"))):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        patterns = {
            "nping_tcp_min_rtt_ms": r"Min rtt:\s*([0-9.]+)\s*ms",
            "nping_tcp_max_rtt_ms": r"Max rtt:\s*([0-9.]+)\s*ms",
            "nping_tcp_avg_rtt_ms": r"Avg rtt:\s*([0-9.]+)\s*ms",
        }
        for metric, pat in patterns.items():
            m = re.search(pat, text, flags=re.IGNORECASE)
            if m:
                add_metric(rows, metric, m.group(1), "ms", rel(path), "Parseado desde nping TCP SYN.")


def parse_cpu_process_summary():
    by_proc = {}
    for path in sorted(glob.glob(os.path.join(raw_dir, "pidstat*.log"))):
        header = None
        in_cpu_table = False
        try:
            for line in open(path, encoding="utf-8", errors="replace"):
                parts = line.split()
                if not parts:
                    continue
                # pidstat -rudw produce varias tablas. Solo se procesa la tabla que contiene %CPU.
                if "Command" in parts:
                    if "%CPU" in parts:
                        header = parts
                        in_cpu_table = True
                    else:
                        in_cpu_table = False
                    continue
                if not in_cpu_table or not header:
                    continue
                if len(parts) > 1 and parts[1] == "UID":
                    continue
                if parts[0] not in ("Average:", "Media:", "Promedio:") and not re.match(r"^\d{1,2}:\d{2}:\d{2}$", parts[0]):
                    continue
                try:
                    cpu_i = header.index("%CPU")
                    cmd_i = header.index("Command")
                    cpu = to_float(parts[cpu_i])
                    cmd = " ".join(parts[cmd_i:]).strip() or "unknown"
                except Exception:
                    continue
                if cpu is None:
                    continue
                item = by_proc.setdefault(cmd, {"cpu_sum": 0.0, "samples": 0, "source": rel(path)})
                item["cpu_sum"] += cpu
                item["samples"] += 1
        except Exception:
            continue
    items = []
    for proc, data in by_proc.items():
        if data["samples"] <= 0:
            continue
        avg = data["cpu_sum"] / data["samples"]
        items.append((proc, avg, data))
    items.sort(key=lambda kv: kv[1], reverse=True)
    rows = []
    cumulative = 0.0
    for rank, (proc, avg, data) in enumerate(items[:12], start=1):
        cumulative += avg
        rows.append({
            "run_id": run_id, "scenario": label, "target": target, "iface": iface,
            "rank": rank, "process": proc, "avg_cpu_pct": fmt(avg),
            "cumulative_cpu_pct": fmt(cumulative), "samples": data["samples"], "source_file": data["source"],
        })
    return rows


def parse_file_inventory():
    rows = []
    skip = {os.path.abspath(dataset_csv), os.path.abspath(interpretation_csv), os.path.abspath(html_report)}
    for root, _, files in os.walk(out_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            if os.path.abspath(path) in skip:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                size = ""
            rows.append(dataset_row("file_inventory", metric="file_size_bytes", value=size, unit="bytes", source_file=rel(path), notes="archivo generado por la corrida"))
    return rows


def status_for_latency_ms(v):
    if v is None:
        return "INFO"
    if v < 50:
        return "OK"
    if v < 100:
        return "WARNING"
    return "ERROR"


def status_for_loss_pct(v):
    if v is None:
        return "INFO"
    if v == 0:
        return "OK"
    if v <= 1:
        return "WARNING"
    return "ERROR"


def interp_row(section, item, metric, value, unit, status, interpretation, recommendation=""):
    return {"run_id": run_id, "scenario": label, "target": target, "iface": iface, "section": section, "item": item, "metric": metric, "value": value, "unit": unit, "status": status, "interpretation": interpretation, "recommendation": recommendation}


def simple_metric_row(metric, label_text, value, unit, source_file, notes=""):
    return {
        "run_id": run_id, "scenario": label, "target": target, "iface": iface,
        "metric": metric, "label": label_text, "value": fmt(value) if to_float(value) is not None else value,
        "unit": unit, "source_file": source_file, "notes": notes,
    }


def build_network_rates_rows(m):
    rows = []
    base_metrics = ["net_rxpck_s", "net_txpck_s", "net_rx_kBps", "net_tx_kBps", "net_ifutil_pct"]
    for metric, r in sorted(m.items()):
        base = metric.split("__", 1)[0]
        if base not in base_metrics:
            continue
        label_text = METRIC_LABELS.get(base, base)
        if "__" in metric:
            label_text += " " + metric.split("__", 1)[1]
        rows.append(simple_metric_row(metric, label_text, r.get("value", ""), r.get("unit", ""), r.get("source_file", ""), r.get("notes", "")))
    return rows

def build_pmtu_loss_rows(m):
    rows = []
    for metric in ["pmtu_payload_max_success", "pmtu_ipv4_approx", "icmp_packet_loss"]:
        r = m.get(metric)
        if r:
            rows.append(simple_metric_row(metric, METRIC_LABELS.get(metric, metric), r.get("value", ""), r.get("unit", ""), r.get("source_file", ""), r.get("notes", "")))
    return rows


def build_tcp_health_rows(m):
    rows = []
    for metric in ["tcp_connect_success_rate", "tcp_connect_avg", "tcp_connect_median", "tcp_connect_p95", "tcp_connect_p99", "tcp_connect_max", "nping_tcp_avg_rtt_ms"]:
        r = m.get(metric)
        if r:
            rows.append(simple_metric_row(metric, METRIC_LABELS.get(metric, metric), r.get("value", ""), r.get("unit", ""), r.get("source_file", ""), r.get("notes", "")))
    return rows


def parse_openssl_speed_summary():
    rows = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "openssl_speed_*.log"))):
        alg = os.path.basename(path).replace("openssl_speed_", "").replace(".log", "")
        best = None
        try:
            for line in open(path, encoding="utf-8", errors="replace"):
                low = line.lower()
                if alg.replace("_", "-").lower() not in low and alg.replace("_", " ").lower() not in low:
                    continue
                nums = []
                for token in line.split():
                    val = to_float(token)
                    if val is not None:
                        nums.append(val)
                if nums:
                    best = max(nums) if best is None else max(best, max(nums))
        except Exception:
            pass
        if best is not None:
            rows.append({
                "run_id": run_id, "scenario": label, "target": target, "iface": iface,
                "algorithm": alg, "throughput_kBps": fmt(best), "source_file": rel(path),
                "notes": "Mayor valor de throughput reportado por openssl speed; unidad original aproximada kB/s."
            })
    return rows


def build_interpretation(m, latency_stats, cpu_rows, packet_rows, iface_rows):
    rows = []
    def get(name):
        row = m.get(name, {})
        return row.get("value", ""), row.get("unit", ""), to_float(row.get("value", ""))

    value, unit, v = get("icmp_packet_loss")
    if value != "":
        st = status_for_loss_pct(v)
        rec = "Mantener como referencia baseline." if st == "OK" else "Revisar estabilidad del enlace, ruta remota o carga durante la medicion."
        rows.append(interp_row("Conectividad", "Perdida ICMP", "icmp_packet_loss", value, unit, st, f"Perdida ICMP observada: {value} {unit}.", rec))

    for metric, item in [("icmp_rtt_avg", "RTT ICMP promedio"), ("tcp_connect_avg", "TCP connect promedio"), ("tcp_connect_p95", "TCP connect p95"), ("tcp_connect_p99", "TCP connect p99")]:
        value, unit, v = get(metric)
        if value != "":
            st = status_for_latency_ms(v)
            rec = "Usar como referencia directa para comparar baseline vs VPN." if st == "OK" else "Revisar cola, retransmisiones, firewall, carga local o ruta remota."
            rows.append(interp_row("Latencia", item, metric, value, unit, st, f"{item}: {value} {unit}.", rec))

    value, unit, v = get("tcp_connect_success_rate")
    if value != "":
        if v is not None and v >= 100:
            st = "OK"; rec = "El puerto TCP fue alcanzable durante todas las muestras."
        elif v is not None and v >= 95:
            st = "WARNING"; rec = "Hubo fallos esporadicos; revisar errores individuales en latency_samples.csv."
        else:
            st = "ERROR"; rec = "Conectividad TCP inestable o servicio no disponible."
        rows.append(interp_row("Servicio TCP", "Tasa de exito TCP connect", "tcp_connect_success_rate", value, unit, st, f"Tasa de exito de establecimiento TCP: {value} {unit}.", rec))

    value, unit, v = get("pmtu_ipv4_approx")
    if value != "":
        if v is not None and v >= 1450:
            st = "OK"; rec = "PMTU cercana a Ethernet estandar."
        elif v is not None and v >= 1360:
            st = "WARNING"; rec = "PMTU reducida, posiblemente por encapsulacion. Ajustar MSS/MTU si aparecen cortes."
        else:
            st = "ERROR"; rec = "PMTU baja; revisar MTU del tunel y fragmentacion."
        rows.append(interp_row("MTU", "PMTU aproximada", "pmtu_ipv4_approx", value, unit, st, f"PMTU IPv4 aproximada: {value} {unit}.", rec))

    value, unit, v = get("payload_entropy")
    if value != "":
        if v is not None and v >= 7.0:
            st = "OK"; rec = "Entropia alta, compatible con payload cifrado o altamente aleatorio."
        elif v is not None and v >= 5.0:
            st = "CHECK"; rec = "Entropia intermedia; complementar con inspeccion de protocolo y puerto capturado."
        else:
            st = "INFO"; rec = "Entropia baja, compatible con trafico estructurado o texto claro."
        rows.append(interp_row("Captura", "Entropia de payload", "payload_entropy", value, unit, st, f"Entropia estimada: {value} {unit}.", rec))

    value, unit, v = get("cpu_avg_busy_pct")
    if value != "":
        if v is not None and v < 50:
            st = "OK"; rec = "No se aprecia saturacion general de CPU."
        elif v is not None and v < 80:
            st = "WARNING"; rec = "Carga moderada; considerar efecto de virtualizacion y procesos concurrentes."
        else:
            st = "ERROR"; rec = "Carga alta; la medicion puede estar afectada por saturacion local."
        rows.append(interp_row("Recursos", "CPU ocupada", "cpu_avg_busy_pct", value, unit, st, f"CPU ocupada promedio: {value} {unit}.", rec))

    if cpu_rows:
        top = cpu_rows[0]
        rows.append(interp_row("Recursos", "Proceso con mayor CPU", "top_process_cpu", top.get("avg_cpu_pct", ""), "%", "INFO", f"El proceso con mayor consumo agregado fue {top.get('process','')} con {top.get('avg_cpu_pct','')} %CPU promedio.", "Comparar el mismo top de procesos entre baseline y VPN."))

    if packet_rows:
        method = packet_rows[0].get("source_method", "")
        rows.append(interp_row("Trafico", "Conteo por servicio", "packet_service_counts", "", "packets", "INFO", f"Se genero conteo de paquetes por servicio usando metodo: {method}.", "Si existe pcap, el conteo es real; si no, se estima desde logs de las pruebas."))

    if iface_rows:
        r = iface_rows[0]
        rows.append(interp_row("Interfaz", "Delta TX/RX", "interface_delta", f"TX {r.get('tx_packets_delta')} / RX {r.get('rx_packets_delta')}", "packets", "INFO", f"Durante la corrida se observo delta de {r.get('tx_packets_delta')} paquetes TX y {r.get('rx_packets_delta')} paquetes RX en {iface}.", "Usar para verificar si la prueba genero trafico real en la interfaz seleccionada."))

    if not rows:
        rows.append(interp_row("General", "Resultado", "", "", "", "INFO", "La corrida genero evidencias, pero no se encontraron metricas suficientes para interpretar automaticamente.", "Revisar raw/, csv/summary.csv y notes.txt."))
    return rows


def metric_value(m, name):
    row = m.get(name)
    if not row:
        return None
    return to_float(row.get("value"))


def status_class(status):
    return str(status or "INFO").lower().replace(" ", "-")


def svg_bar_chart(title, items, unit="", width=920, bar_h=26):
    clean = [(str(lbl), to_float(val)) for lbl, val in items if to_float(val) is not None]
    if not clean:
        return f"<p class='muted'>No hay datos suficientes para {esc(title)}.</p>"
    max_v = max(v for _, v in clean) or 1.0
    height = 55 + len(clean) * 44
    x0 = 260
    lines = [f"<h3>{esc(title)}</h3>", f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='{esc(title)}'>"]
    lines.append(f"<line x1='{x0}' y1='24' x2='{width-90}' y2='24' class='axis'/>")
    y = 42
    for lbl, val in clean:
        bw = max(2, (width - x0 - 140) * val / max_v)
        lines.append(f"<text x='12' y='{y+18}' class='svg-label'>{esc(lbl)}</text>")
        lines.append(f"<rect x='{x0}' y='{y}' width='{bw:.1f}' height='{bar_h}' rx='5' class='bar'></rect>")
        lines.append(f"<text x='{x0+bw+10:.1f}' y='{y+18}' class='svg-value'>{esc(fmt(val))} {esc(unit)}</text>")
        y += 44
    lines.append("</svg>")
    return "\n".join(lines)


def svg_service_packet_chart(packet_rows):
    agg = {}
    method = ""
    for r in packet_rows:
        direction = r.get("direction", "")
        if direction not in ("sent_to_target", "connection_attempts", "probe_cycles"):
            continue
        service = r.get("service", "UNKNOWN")
        val = to_float(r.get("packets"))
        if val is None:
            continue
        agg[service] = agg.get(service, 0.0) + val
        method = r.get("source_method", method)
    note = "Conteo real desde pcap." if method == "pcap_tshark" else "Conteo estimado desde logs cuando no existe pcap o no esta disponible tshark."
    return svg_bar_chart("Paquetes enviados por servicio", sorted(agg.items()), "packets") + f"<p class='muted'>{esc(note)}</p>"


def svg_boxplot(title, stats_rows, width=1080, height=None):
    rows = []
    for r in stats_rows:
        vals = {k: to_float(r.get(k)) for k in ["min_ms", "q1_ms", "median_ms", "mean_ms", "q3_ms", "ci95_low_ms", "ci95_high_ms", "max_ms"]}
        if vals["max_ms"] is not None:
            rows.append((r.get("service", ""), vals, int(to_float(r.get("n")) or 0)))
    if not rows:
        return f"<p class='muted'>No hay datos suficientes para {esc(title)}.</p>"
    height = height or (120 + len(rows) * 92)
    max_v = max(vals["max_ms"] for _, vals, _ in rows if vals["max_ms"] is not None) or 1.0
    plot_x0 = 185
    plot_x1 = width - 55
    top = 62
    row_h = 84
    def x(v):
        return plot_x0 + (plot_x1 - plot_x0) * (v or 0) / max_v
    lines = [f"<h3>{esc(title)}</h3>", f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='{esc(title)}'>"]
    lines.append(f"<text x='{plot_x0}' y='28' class='svg-label'>Escala: 0 a {fmt(max_v)} ms. La tabla inferior contiene media, mediana e IC95.</text>")
    for t in range(6):
        xv = plot_x0 + (plot_x1 - plot_x0) * t / 5
        val = max_v * t / 5
        lines.append(f"<line x1='{xv:.1f}' y1='{top-20}' x2='{xv:.1f}' y2='{height-42}' class='gridline'/>")
        lines.append(f"<text x='{xv-12:.1f}' y='{height-20}' class='svg-label'>{fmt(val,2)}</text>")
    for i, (service, vals, n) in enumerate(rows):
        cy = top + i * row_h + 28
        box_h = 24
        lines.append(f"<text x='18' y='{cy+5:.1f}' class='svg-label'>{esc(service)}  n={n}</text>")
        lines.append(f"<line x1='{x(vals['min_ms']):.1f}' y1='{cy:.1f}' x2='{x(vals['max_ms']):.1f}' y2='{cy:.1f}' class='whisker'/>")
        lines.append(f"<line x1='{x(vals['min_ms']):.1f}' y1='{cy-9:.1f}' x2='{x(vals['min_ms']):.1f}' y2='{cy+9:.1f}' class='whisker'/>")
        lines.append(f"<line x1='{x(vals['max_ms']):.1f}' y1='{cy-9:.1f}' x2='{x(vals['max_ms']):.1f}' y2='{cy+9:.1f}' class='whisker'/>")
        lines.append(f"<rect x='{x(vals['q1_ms']):.1f}' y='{cy-box_h/2:.1f}' width='{max(2, x(vals['q3_ms'])-x(vals['q1_ms'])):.1f}' height='{box_h}' rx='4' class='box'></rect>")
        lines.append(f"<line x1='{x(vals['median_ms']):.1f}' y1='{cy-box_h/2:.1f}' x2='{x(vals['median_ms']):.1f}' y2='{cy+box_h/2:.1f}' class='median'/>")
        lines.append(f"<circle cx='{x(vals['mean_ms']):.1f}' cy='{cy:.1f}' r='5' class='mean'/>")
        if vals['ci95_low_ms'] is not None and vals['ci95_high_ms'] is not None:
            lines.append(f"<line x1='{x(vals['ci95_low_ms']):.1f}' y1='{cy+26:.1f}' x2='{x(vals['ci95_high_ms']):.1f}' y2='{cy+26:.1f}' class='ci'/>")
        lines.append(f"<text x='{plot_x0}' y='{cy+49:.1f}' class='svg-label'>min {fmt(vals['min_ms'])} | Q1 {fmt(vals['q1_ms'])} | med {fmt(vals['median_ms'])} | mean {fmt(vals['mean_ms'])} | Q3 {fmt(vals['q3_ms'])} | max {fmt(vals['max_ms'])}</text>")
    lines.append(f"<text x='{plot_x0}' y='{height-2}' class='svg-label'>Caja: Q1-Q3 | linea negra: mediana | punto rojo: media | linea punteada: IC95</text>")
    lines.append("</svg>")
    return "\n".join(lines)


def svg_cpu_combo(cpu_rows, width=920, height=360):
    if not cpu_rows:
        return "<p class='muted'>No hay datos suficientes para CPU por proceso. Esto requiere pidstat.</p>"
    rows = cpu_rows[:10]
    max_v = max(to_float(r.get("cumulative_cpu_pct")) or 0 for r in rows) or 1.0
    x0, y0 = 70, 40
    plot_w, plot_h = width - 120, 220
    bar_w = plot_w / max(len(rows), 1) * 0.58
    def y(v):
        return y0 + plot_h - (plot_h * (v or 0) / max_v)
    lines = ["<h3>CPU por proceso y CPU acumulada</h3>", f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='CPU por proceso y acumulada'>"]
    lines.append(f"<line x1='{x0}' y1='{y0+plot_h}' x2='{x0+plot_w}' y2='{y0+plot_h}' class='axis'/>")
    lines.append(f"<line x1='{x0}' y1='{y0}' x2='{x0}' y2='{y0+plot_h}' class='axis'/>")
    pts = []
    for i, r in enumerate(rows):
        cpu = to_float(r.get("avg_cpu_pct")) or 0
        cum = to_float(r.get("cumulative_cpu_pct")) or 0
        cx = x0 + (i + 0.5) * plot_w / len(rows)
        bx = cx - bar_w / 2
        bh = y0 + plot_h - y(cpu)
        lines.append(f"<rect x='{bx:.1f}' y='{y(cpu):.1f}' width='{bar_w:.1f}' height='{bh:.1f}' class='bar-cpu'></rect>")
        lines.append(f"<text x='{cx:.1f}' y='{y0+plot_h+42}' class='svg-label rotate' transform='rotate(35 {cx:.1f},{y0+plot_h+42})'>{esc(r.get('process','')[:18])}</text>")
        lines.append(f"<text x='{bx:.1f}' y='{max(16, y(cpu)-6):.1f}' class='svg-value'>{fmt(cpu)}%</text>")
        pts.append((cx, y(cum)))
    if pts:
        d = " ".join(f"{x:.1f},{yy:.1f}" for x, yy in pts)
        lines.append(f"<polyline points='{d}' class='line-total'/>")
        for xpt, ypt in pts:
            lines.append(f"<circle cx='{xpt:.1f}' cy='{ypt:.1f}' r='4' class='point-total'/>")
    lines.append(f"<text x='{x0}' y='25' class='svg-label'>Barras: %CPU por proceso. Linea: %CPU acumulado.</text>")
    lines.append("</svg>")
    return "\n".join(lines)


def svg_latency_timeseries(samples, width=1080, height=390):
    by = {}
    for r in samples:
        v = to_float(r.get("value_ms"))
        if v is None:
            continue
        by.setdefault(r.get("service", "UNKNOWN"), []).append(v)
    if not by:
        return "<p class='muted'>No hay muestras suficientes para serie temporal de latencia.</p>"
    vals_all = [v for vals in by.values() for v in vals]
    max_v = max(vals_all) or 1.0
    min_v = min(vals_all) if vals_all else 0.0
    pad = (max_v - min_v) * 0.08 or 1.0
    y_min, y_max = max(0.0, min_v - pad), max_v + pad
    x0, y0 = 70, 50
    plot_w, plot_h = width - 120, height - 115
    def y(v):
        return y0 + plot_h - plot_h * (v - y_min) / (y_max - y_min or 1.0)
    def smooth(vals, win=7):
        if len(vals) < win:
            return vals[:]
        out = []
        half = win // 2
        for i in range(len(vals)):
            lo = max(0, i-half); hi = min(len(vals), i+half+1)
            out.append(sum(vals[lo:hi])/(hi-lo))
        return out
    def downsample(vals, limit=750):
        if len(vals) <= limit:
            return vals
        step = len(vals) / limit
        return [vals[int(i*step)] for i in range(limit)]
    colors = ["line-a", "line-b", "line-c", "line-d"]
    lines = ["<h3>Serie temporal de latencia por servicio</h3>", f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='Serie temporal de latencia'>"]
    lines.append(f"<line x1='{x0}' y1='{y0+plot_h}' x2='{x0+plot_w}' y2='{y0+plot_h}' class='axis'/>")
    lines.append(f"<line x1='{x0}' y1='{y0}' x2='{x0}' y2='{y0+plot_h}' class='axis'/>")
    for t in range(6):
        yy = y0 + plot_h * t / 5
        val = y_max - (y_max - y_min) * t / 5
        lines.append(f"<line x1='{x0}' y1='{yy:.1f}' x2='{x0+plot_w}' y2='{yy:.1f}' class='gridline'/>")
        lines.append(f"<text x='12' y='{yy+4:.1f}' class='svg-label'>{fmt(val,2)} ms</text>")
    legend_x = x0
    for idx, (service, vals) in enumerate(sorted(by.items())):
        vals_s = downsample(smooth(vals))
        if not vals_s:
            continue
        pts = []
        n = len(vals_s)
        for i, v in enumerate(vals_s):
            x = x0 + (plot_w * i / max(1, n-1))
            pts.append(f"{x:.1f},{y(v):.1f}")
        klass = colors[idx % len(colors)]
        lines.append(f"<polyline points='{' '.join(pts)}' class='{klass}'/>")
        lines.append(f"<text x='{legend_x}' y='{24 + idx*18}' class='svg-label'>{esc(service)}: {len(vals)} muestras, linea suavizada</text>")
    lines.append(f"<text x='{x0}' y='{height-20}' class='svg-label'>Cada servicio se normaliza a todo el ancho del grafico. Eje Y: latencia en ms. Rango {fmt(y_min)} a {fmt(y_max)} ms.</text>")
    lines.append("</svg>")
    return "\n".join(lines)


def svg_interface_delta(iface_rows):
    if not iface_rows:
        return "<p class='muted'>No hay delta de interfaz disponible.</p>"
    items = []
    for r in iface_rows:
        ifn = r.get("iface", "iface")
        items.extend([
            (f"{ifn} TX packets", r.get("tx_packets_delta")),
            (f"{ifn} RX packets", r.get("rx_packets_delta")),
            (f"{ifn} TX bytes", r.get("tx_bytes_delta")),
            (f"{ifn} RX bytes", r.get("rx_bytes_delta")),
        ])
    return svg_bar_chart("Delta de trafico por interfaz", items, "")

def svg_simple_metric_bars(title, rows, unit_filter=None, width=920):
    items = []
    for r in rows:
        val = to_float(r.get("value"))
        if val is None:
            continue
        if unit_filter and r.get("unit") != unit_filter:
            continue
        label_text = r.get("label") or r.get("metric")
        unit = r.get("unit", "")
        items.append((f"{label_text} ({unit})" if unit else label_text, val))
    return svg_bar_chart(title, items, "", width=width)


def svg_tcp_health(tcp_rows):
    return svg_simple_metric_bars("Salud del servicio TCP", tcp_rows)


def svg_pmtu_loss(pmtu_rows):
    return svg_simple_metric_bars("PMTU y perdida", pmtu_rows)


def svg_network_rates(net_rows):
    return svg_simple_metric_bars("Tasas promedio de red en la interfaz", net_rows)


def svg_crypto_speed(crypto_rows):
    items = []
    for r in crypto_rows:
        v = to_float(r.get("throughput_kBps"))
        if v is not None:
            items.append((r.get("algorithm", "unknown"), v))
    return svg_bar_chart("Throughput criptografico local openssl", items, "kB/s")


def svg_iperf_summary(m):
    rows = []
    for metric in ["iperf3_tcp_bits_per_second", "iperf3_udp_bits_per_second", "iperf3_udp_jitter_ms", "iperf3_udp_lost_percent", "iperf3_tcp_retransmits"]:
        r = m.get(metric)
        if r:
            rows.append(simple_metric_row(metric, METRIC_LABELS.get(metric, metric), r.get("value", ""), r.get("unit", ""), r.get("source_file", ""), r.get("notes", "")))
    if not rows:
        return "<p class='muted'>No hay datos iperf3 porque no se ejecuto --iperf-server o no hubo servidor iperf3 autorizado.</p>"
    return svg_simple_metric_bars("Throughput, jitter y perdida iperf3", rows)


def table_html(headers, rows, limit=None):
    rows = rows[:limit] if limit else rows
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{esc(row.get(h, ''))}</td>" for h in headers) + "</tr>")
    if not body:
        body.append(f"<tr><td colspan='{len(headers)}'>Sin datos disponibles.</td></tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def build_html_report(metrics_rows, interp_rows, dataset_rows, packet_rows, latency_samples, latency_stats, cpu_rows, iface_rows, key_rows, network_rows, pmtu_rows, tcp_rows, crypto_rows):
    m = metric_map(metrics_rows)
    key_headers = ["label", "metric", "value", "unit", "source_file"]
    key_table = table_html(key_headers, key_rows)
    interp_table = "<table><thead><tr><th>Seccion</th><th>Item</th><th>Estado</th><th>Valor</th><th>Interpretacion</th><th>Recomendacion</th></tr></thead><tbody>"
    for r in interp_rows:
        interp_table += f"<tr><td>{esc(r['section'])}</td><td>{esc(r['item'])}</td><td><span class='badge {status_class(r['status'])}'>{esc(r['status'])}</span></td><td>{esc(r['value'])} {esc(r['unit'])}</td><td>{esc(r['interpretation'])}</td><td>{esc(r['recommendation'])}</td></tr>"
    interp_table += "</tbody></table>"

    latency_stat_table = table_html(["service", "n", "min_ms", "q1_ms", "median_ms", "mean_ms", "q3_ms", "p95_ms", "p99_ms", "max_ms", "ci95_low_ms", "ci95_high_ms"], latency_stats)
    cpu_table = table_html(["rank", "process", "avg_cpu_pct", "cumulative_cpu_pct", "samples", "source_file"], cpu_rows, limit=12)
    packet_table = table_html(["source_method", "service", "direction", "packets", "bytes", "notes"], packet_rows)
    iface_table = table_html(["iface", "tx_packets_delta", "rx_packets_delta", "tx_bytes_delta", "rx_bytes_delta", "source_file"], iface_rows)
    network_table = table_html(["label", "metric", "value", "unit", "source_file"], network_rows)
    pmtu_table = table_html(["label", "metric", "value", "unit", "source_file"], pmtu_rows)
    tcp_table = table_html(["label", "metric", "value", "unit", "source_file"], tcp_rows)
    crypto_table = table_html(["algorithm", "throughput_kBps", "source_file", "notes"], crypto_rows)

    dataset_counts = {}
    for r in dataset_rows:
        dataset_counts[r.get("record_type", "unknown")] = dataset_counts.get(r.get("record_type", "unknown"), 0) + 1
    dataset_count_html = "".join(f"<li><strong>{esc(k)}</strong>: {v}</li>" for k, v in sorted(dataset_counts.items()))

    notes_text = ""
    notes_path = os.path.join(out_dir, "notes.txt")
    if os.path.isfile(notes_path):
        try:
            notes_text = open(notes_path, encoding="utf-8", errors="replace").read().strip()
        except Exception:
            notes_text = ""

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Reporte SCADA VPN Probe - {esc(label)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; line-height: 1.45; color: #1f2933; }}
h1, h2, h3 {{ color: #102a43; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
.card {{ border: 1px solid #d9e2ec; border-radius: 12px; padding: 16px; background: #f8fafc; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0 24px 0; font-size: 13px; }}
th, td {{ border: 1px solid #d9e2ec; padding: 8px; vertical-align: top; }}
th {{ background: #eef2f7; text-align: left; }}
code {{ background: #eef2f7; padding: 2px 4px; border-radius: 4px; }}
.badge {{ display: inline-block; border-radius: 999px; padding: 3px 8px; font-weight: bold; font-size: 12px; }}
.ok {{ background: #dcfce7; color: #166534; }}
.warning {{ background: #fef3c7; color: #92400e; }}
.error {{ background: #fee2e2; color: #991b1b; }}
.check {{ background: #e0f2fe; color: #075985; }}
.info {{ background: #e5e7eb; color: #374151; }}
svg {{ width: 100%; max-width: 980px; height: auto; border: 1px solid #d9e2ec; border-radius: 12px; background: #ffffff; margin-bottom: 18px; }}
.axis {{ stroke: #9fb3c8; stroke-width: 1; }}
.gridline {{ stroke: #e5e7eb; stroke-width: 1; }}
.bar {{ fill: #3b82f6; }}
.bar-cpu {{ fill: #94a3b8; }}
.box {{ fill: #bfdbfe; stroke: #1d4ed8; stroke-width: 1; }}
.whisker {{ stroke: #1d4ed8; stroke-width: 2; }}
.median {{ stroke: #111827; stroke-width: 3; }}
.mean {{ fill: #ef4444; }}
.ci {{ stroke: #0ea5e9; stroke-width: 4; stroke-dasharray: 6 4; }}
.line-total {{ fill: none; stroke: #2563eb; stroke-width: 3; }}
.point-total {{ fill: #2563eb; }}
.line-a {{ fill: none; stroke: #2563eb; stroke-width: 1.7; }}
.line-b {{ fill: none; stroke: #16a34a; stroke-width: 1.7; }}
.line-c {{ fill: none; stroke: #dc2626; stroke-width: 1.7; }}
.line-d {{ fill: none; stroke: #9333ea; stroke-width: 1.7; }}
.svg-label {{ font-size: 13px; fill: #334e68; }}
.svg-value {{ font-size: 13px; fill: #102a43; font-weight: bold; }}
.muted {{ color: #627d98; }}
pre {{ white-space: pre-wrap; background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 8px; padding: 12px; }}
@media print {{ body {{ margin: 16px; }} .card, svg {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<h1>Reporte interpretado SCADA VPN Probe</h1>
<div class="grid">
  <div class="card"><strong>Escenario</strong><br>{esc(label)}</div>
  <div class="card"><strong>Target</strong><br>{esc(target)}:{esc(port)}</div>
  <div class="card"><strong>Interfaz</strong><br>{esc(iface)}</div>
  <div class="card"><strong>Duracion</strong><br>{esc(duration)} s</div>
  <div class="card"><strong>Run ID</strong><br><code>{esc(run_id)}</code></div>
  <div class="card"><strong>Generado</strong><br>{esc(generated_at)}</div>
</div>

<h2>1. Lectura tecnica consolidada</h2>
{interp_table}

<h2>2. Metricas clave comparables</h2>
<p>Estas metricas deben compararse entre corridas con la misma duracion, mismo target, misma interfaz equivalente y mismas opciones del script.</p>
{key_table}

<h2>3. Paquetes enviados por servicio</h2>
<p>La barra representa trafico enviado hacia el objetivo. Si hay captura, se usa el pcap; si no, se estima desde los logs generados por cada prueba.</p>
{svg_service_packet_chart(packet_rows)}
{packet_table}

<h2>4. Latencias por tipo de mensaje</h2>
<p>El boxplot muestra minimo, Q1, mediana, media, Q3, maximo e intervalo de confianza del 95 %. Sirve para comparar estabilidad, no solo promedio.</p>
{svg_boxplot('Boxplot de latencia por servicio', latency_stats)}
{svg_latency_timeseries(latency_samples)}
{latency_stat_table}

<h2>5. Rendimiento de CPU</h2>
<p>Las barras muestran CPU promedio por proceso. La linea muestra el acumulado de CPU conforme se agregan los procesos de mayor consumo.</p>
{svg_cpu_combo(cpu_rows)}
{cpu_table}

<h2>6. Trafico total de interfaz</h2>
<p>Este grafico sirve para validar si la interfaz seleccionada realmente movio trafico durante la corrida.</p>
{svg_interface_delta(iface_rows)}
{iface_table}

<h2>7. Graficas adicionales para comparar pruebas</h2>
<p>Estas graficas ya se generan en el HTML. Si una aparece sin datos, significa que esa prueba no produjo evidencia suficiente o no fue ejecutada en esa corrida.</p>
{svg_tcp_health(tcp_rows)}
{tcp_table}
{svg_pmtu_loss(pmtu_rows)}
{pmtu_table}
{svg_network_rates(network_rows)}
{network_table}
{svg_iperf_summary(metric_map(metrics_rows))}
{svg_crypto_speed(crypto_rows)}
{crypto_table}

<h2>8. Archivos de salida principales</h2>
<ul>
  <li><code>csv/probe_dataset.csv</code>: CSV maestro consolidado.</li>
  <li><code>csv/probe_interpretation.csv</code>: lectura tecnica automatica.</li>
  <li><code>csv/packet_service_counts.csv</code>: paquetes por servicio.</li>
  <li><code>csv/latency_samples.csv</code>: muestras de latencia.</li>
  <li><code>csv/latency_stats.csv</code>: estadisticos para boxplot e IC95.</li>
  <li><code>csv/cpu_process_summary.csv</code>: CPU por proceso y acumulado.</li>
  <li><code>csv/interface_delta.csv</code>: paquetes y bytes TX/RX de la interfaz.</li>
</ul>
<p>Tipos de registros en el CSV maestro:</p>
<ul>{dataset_count_html}</ul>

<h2>9. Notas y advertencias</h2>
<pre>{esc(notes_text) if notes_text else 'Sin notas registradas.'}</pre>
</body>
</html>"""


# Pipeline de consolidacion
metrics_rows = parse_summary_metrics()
parse_sar_cpu(metrics_rows)
parse_sar_net(metrics_rows)
parse_nping(metrics_rows)

iface_rows = parse_interface_delta()
for r in iface_rows:
    ifn = r.get("iface", primary_iface)
    suffix = iface_metric_suffix(ifn)
    add_metric(metrics_rows, "interface_tx_packets_delta" + suffix, r.get("tx_packets_delta"), "packets", r.get("source_file"), f"Delta TX en {ifn}.")
    add_metric(metrics_rows, "interface_rx_packets_delta" + suffix, r.get("rx_packets_delta"), "packets", r.get("source_file"), f"Delta RX en {ifn}.")
    add_metric(metrics_rows, "interface_tx_bytes_delta" + suffix, r.get("tx_bytes_delta"), "bytes", r.get("source_file"), f"Delta TX en {ifn}.")
    add_metric(metrics_rows, "interface_rx_bytes_delta" + suffix, r.get("rx_bytes_delta"), "bytes", r.get("source_file"), f"Delta RX en {ifn}.")

tcp_dataset, tcp_samples = parse_tcp_connect_samples()
icmp_dataset, icmp_samples = parse_icmp_ping_samples()
latency_samples = icmp_samples + tcp_samples
latency_stats = build_latency_stats(latency_samples)

packet_rows = run_tshark_packet_counts()
if not packet_rows:
    packet_rows = estimated_packet_counts(latency_samples)

cpu_rows = parse_cpu_process_summary()

# key metrics compactas
m_tmp = metric_map(metrics_rows)
key_order = [
    "icmp_packet_loss", "icmp_rtt_avg", "icmp_rtt_mdev",
    "tcp_connect_success_rate", "tcp_connect_avg", "tcp_connect_p95", "tcp_connect_p99",
    "pmtu_ipv4_approx", "payload_entropy", "cpu_avg_busy_pct", "net_rx_kBps", "net_tx_kBps",
    "net_rxpck_s", "net_txpck_s", "interface_tx_packets_delta", "interface_rx_packets_delta",
    "iperf3_tcp_bits_per_second", "iperf3_udp_jitter_ms", "iperf3_udp_lost_percent",
]
key_rows = []
for k in key_order:
    r = m_tmp.get(k)
    if not r:
        continue
    key_rows.append({
        "run_id": run_id, "scenario": label, "target": target, "iface": iface,
        "metric": k, "label": METRIC_LABELS.get(k, k), "value": r.get("value", ""),
        "unit": r.get("unit", ""), "source_file": r.get("source_file", ""), "notes": r.get("notes", "")
    })
# En modo multi-interfaz, agrega métricas por interfaz al bloque comparable.
for k, r in sorted(m_tmp.items()):
    base = k.split("__", 1)[0]
    if "__" in k and (base.startswith("net_") or base.startswith("interface_")):
        if any(row.get("metric") == k for row in key_rows):
            continue
        label_text = METRIC_LABELS.get(base, base) + " " + k.split("__", 1)[1]
        key_rows.append({
            "run_id": run_id, "scenario": label, "target": target, "iface": iface,
            "metric": k, "label": label_text, "value": r.get("value", ""),
            "unit": r.get("unit", ""), "source_file": r.get("source_file", ""), "notes": r.get("notes", "")
        })

# CSVs auxiliares para graficas adicionales
m_tmp = metric_map(metrics_rows)
network_rows = build_network_rates_rows(m_tmp)
pmtu_rows = build_pmtu_loss_rows(m_tmp)
tcp_rows = build_tcp_health_rows(m_tmp)
crypto_rows = parse_openssl_speed_summary()

# Dataset maestro
dataset_rows = []
dataset_rows.extend(metrics_rows)
dataset_rows.extend(icmp_dataset)
dataset_rows.extend(tcp_dataset)
for r in packet_rows:
    dataset_rows.append(dataset_row("packet_count", service=r.get("service", ""), metric="packets", value=r.get("packets", ""), unit="packets", status=r.get("direction", ""), source_file=r.get("source_method", ""), notes=r.get("notes", "")))
for r in latency_stats:
    dataset_rows.append(dataset_row("latency_stats", service=r.get("service", ""), metric="mean_ms", value=r.get("mean_ms", ""), unit="ms", source_file=r.get("source_file", ""), notes="estadisticos de latencia para boxplot"))
for r in cpu_rows:
    dataset_rows.append(dataset_row("cpu_process", service=r.get("process", ""), metric="avg_cpu_pct", value=r.get("avg_cpu_pct", ""), unit="%", sample=r.get("rank", ""), source_file=r.get("source_file", ""), notes="CPU promedio por proceso y acumulado"))
for r in iface_rows:
    dataset_rows.append(dataset_row("interface_delta", service=iface, metric="tx_packets_delta", value=r.get("tx_packets_delta", ""), unit="packets", source_file=r.get("source_file", ""), notes="Delta de contadores de interfaz"))

dataset_rows.extend(parse_file_inventory())
interp_rows = build_interpretation(metric_map(metrics_rows), latency_stats, cpu_rows, packet_rows, iface_rows)

# Escritura de CSVs
write_csv(dataset_csv, DATASET_FIELDS, dataset_rows)
write_csv(interpretation_csv, INTERPRETATION_FIELDS, interp_rows)
write_csv(packet_counts_csv, PACKET_FIELDS, packet_rows)
write_csv(latency_samples_csv, LATENCY_SAMPLE_FIELDS, latency_samples)
write_csv(latency_stats_csv, LATENCY_STATS_FIELDS, latency_stats)
write_csv(cpu_process_csv, CPU_FIELDS, cpu_rows)
write_csv(interface_delta_csv, IFACE_FIELDS, iface_rows)
write_csv(key_metrics_csv, KEY_FIELDS, key_rows)
write_csv(network_rates_csv, SIMPLE_METRIC_FIELDS, network_rows)
write_csv(pmtu_loss_csv, SIMPLE_METRIC_FIELDS, pmtu_rows)
write_csv(tcp_health_csv, SIMPLE_METRIC_FIELDS, tcp_rows)
write_csv(crypto_speed_csv, CRYPTO_FIELDS, crypto_rows)

# HTML final
with open(html_report, "w", encoding="utf-8") as f:
    f.write(build_html_report(metrics_rows, interp_rows, dataset_rows, packet_rows, latency_samples, latency_stats, cpu_rows, iface_rows, key_rows, network_rows, pmtu_rows, tcp_rows, crypto_rows))
PYREPORT
}


write_readme() {
  cat > "${OUT_DIR}/README.txt" <<EOF
SCADA VPN Probe - Evidencia de medición

Escenario: $LABEL
Target: $TARGET
Puerto: $PORT
Interfaz(es): $IFACE_SPEC
Duración: $DURATION segundos
Inicio: $START_STAMP

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
EOF
}

main() {
  echo "[INFO] SCADA VPN Probe v${VERSION}"
  echo "[INFO] Resultados en: ${OUT_DIR}"

  write_metadata
  collect_before_snapshots
  start_monitors
  start_capture

  # Se da un margen para que monitores y captura arranquen.
  sleep 2

  run_vpn_specific_status
  run_trace_tests
  run_pmtu_test
  run_ping_test
  run_tcp_connect_test
  run_nping_or_hping
  run_iperf_test
  run_openssl_speed

  # Esperar a que monitores de duración fija terminen.
  echo "[INFO] Esperando cierre de monitores/captura..."
  sleep 2
  stop_bg

  collect_after_snapshots
  entropy_from_pcap
  parse_results
  write_readme
  write_consolidated_outputs

  echo "[INFO] Finalizado."
  echo "[INFO] Resumen: ${SUMMARY}"
  echo "[INFO] CSV consolidado: ${REPORT_CSV}"
  echo "[INFO] CSV interpretado: ${INTERPRETATION_CSV}"
  echo "[INFO] Informe HTML: ${HTML_REPORT}"
  echo "[INFO] Carpeta: ${OUT_DIR}"
}

main "$@"
