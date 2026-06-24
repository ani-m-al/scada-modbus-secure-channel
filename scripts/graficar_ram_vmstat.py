from pathlib import Path
import argparse
import csv
import math
import re
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


AVG_TOKENS = {"Average:", "Media:", "Promedio:"}


def to_float(value):
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    text = text.replace("%", "")

    if "," in text:
        text = text.replace(".", "").replace(",", ".")

    try:
        return float(text)
    except ValueError:
        return None


def percentile(values, p):
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None

    if len(vals) == 1:
        return vals[0]

    k = (len(vals) - 1) * p / 100.0
    f = math.floor(k)
    c = min(f + 1, len(vals) - 1)

    if f == c:
        return vals[f]

    return vals[f] + (vals[c] - vals[f]) * (k - f)


def basic_stats(values):
    vals = [v for v in values if v is not None]

    if not vals:
        return {
            "n": 0,
            "min": "",
            "mean": "",
            "median": "",
            "p95": "",
            "max": "",
            "std": "",
        }

    return {
        "n": len(vals),
        "min": min(vals),
        "mean": statistics.mean(vals),
        "median": statistics.median(vals),
        "p95": percentile(vals, 95),
        "max": max(vals),
        "std": statistics.stdev(vals) if len(vals) > 1 else 0.0,
    }


def fmt(value, decimals=3):
    if value is None or value == "":
        return ""

    try:
        value = float(value)
    except Exception:
        return str(value)

    return f"{value:.{decimals}f}"


def write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def safe_filename(text):
    text = str(text)
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")[:180]


def infer_interval_seconds(run_dir):
    text = read_text(run_dir / "metadata.txt")
    match = re.search(r"interval_seconds\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else 1


def infer_label(run_dir):
    text = read_text(run_dir / "metadata.txt")
    match = re.search(r"scenario_label\s*=\s*(.+)", text)
    return match.group(1).strip() if match else ""


def infer_target(run_dir):
    text = read_text(run_dir / "metadata.txt")
    match = re.search(r"target\s*=\s*(.+)", text)
    return match.group(1).strip() if match else ""


def infer_iface(run_dir):
    text = read_text(run_dir / "metadata.txt")
    match = re.search(r"iface\s*=\s*(.+)", text)
    return match.group(1).strip() if match else ""


def infer_mem_total_kib(run_dir):
    """
    Busca MemTotal si existe en algún log.
    Si no existe, usar --mem-total-mib.
    """
    candidates = [
        run_dir / "raw" / "proc_meminfo.log",
        run_dir / "metadata.txt",
    ]

    for path in candidates:
        text = read_text(path)
        match = re.search(r"MemTotal:\s+(\d+)\s+kB", text)
        if match:
            return int(match.group(1))

    return None


def find_runs(root):
    root = Path(root)

    if (root / "raw" / "vmstat.log").exists():
        return [root]

    runs = []
    for vmstat_path in root.rglob("raw/vmstat.log"):
        runs.append(vmstat_path.parent.parent)

    return sorted(set(runs))


def make_run_title(run_dir):
    label = infer_label(run_dir)
    target = infer_target(run_dir)
    iface = infer_iface(run_dir)

    parts = []

    if label:
        parts.append(label)

    if target:
        parts.append(target)

    if iface:
        parts.append(f"iface={iface}")

    parts.append(run_dir.name)

    return " | ".join(parts)


def parse_vmstat(vmstat_path, interval_seconds=1, mem_total_kib=None, keep_first=False):
    text = read_text(vmstat_path)
    header = None
    samples = []

    for line in text.splitlines():
        parts = line.split()

        if not parts:
            continue

        if {"swpd", "free", "buff", "cache", "si", "so"}.issubset(set(parts)):
            header = parts
            continue

        if header is None:
            continue

        if not re.match(r"^-?\d+$", parts[0]):
            continue

        if len(parts) > len(header):
            parts = parts[-len(header):]

        if len(parts) < len(header):
            continue

        row = {}
        valid = True

        for key, value in zip(header, parts):
            number = to_float(value)
            if number is None:
                valid = False
                break
            row[key] = number

        if valid:
            samples.append(row)

    # Primera fila de vmstat suele ser promedio desde arranque.
    if samples and not keep_first:
        samples = samples[1:]

    parsed = []

    for idx, row in enumerate(samples, start=1):
        swpd_kib = row.get("swpd", 0.0)
        free_kib = row.get("free", 0.0)
        buff_kib = row.get("buff", 0.0)
        cache_kib = row.get("cache", 0.0)

        available_proxy_kib = free_kib + buff_kib + cache_kib

        result = {
            "sample": idx,
            "elapsed_s": (idx - 1) * interval_seconds,

            "swpd_mib": swpd_kib / 1024.0,
            "free_mib": free_kib / 1024.0,
            "buff_mib": buff_kib / 1024.0,
            "cache_mib": cache_kib / 1024.0,
            "available_proxy_mib": available_proxy_kib / 1024.0,

            "swap_in_kib_s": row.get("si", 0.0),
            "swap_out_kib_s": row.get("so", 0.0),

            "blocks_in_s": row.get("bi", 0.0),
            "blocks_out_s": row.get("bo", 0.0),

            "interrupts_s": row.get("in", 0.0),
            "context_switches_s": row.get("cs", 0.0),

            "cpu_user_pct": row.get("us", 0.0),
            "cpu_system_pct": row.get("sy", 0.0),
            "cpu_idle_pct": row.get("id", 0.0),
            "cpu_iowait_pct": row.get("wa", 0.0),
        }

        if mem_total_kib:
            used_including_cache_kib = mem_total_kib - free_kib
            used_without_cache_kib = mem_total_kib - free_kib - buff_kib - cache_kib

            result.update({
                "mem_total_mib": mem_total_kib / 1024.0,

                # Linux usa cache agresivamente; esta métrica incluye cache.
                "used_including_cache_mib": used_including_cache_kib / 1024.0,
                "used_including_cache_pct": (used_including_cache_kib / mem_total_kib) * 100.0,

                # Esta se parece más a consumo real de aplicaciones/kernel.
                "used_without_buffer_cache_mib": used_without_cache_kib / 1024.0,
                "used_without_buffer_cache_pct": (used_without_cache_kib / mem_total_kib) * 100.0,
            })

        parsed.append(result)

    return parsed


def summarize_vmstat(samples):
    metric_defs = [
        ("swpd_mib", "Swap usada", "MiB"),
        ("free_mib", "Memoria libre", "MiB"),
        ("buff_mib", "Buffers", "MiB"),
        ("cache_mib", "Cache", "MiB"),
        ("available_proxy_mib", "Libre + buffers + cache", "MiB"),
        ("swap_in_kib_s", "Swap in", "KiB/s"),
        ("swap_out_kib_s", "Swap out", "KiB/s"),
        ("context_switches_s", "Cambios de contexto", "cambios/s"),
    ]

    if samples and "used_including_cache_mib" in samples[0]:
        metric_defs.extend([
            ("used_including_cache_mib", "RAM usada incluyendo cache", "MiB"),
            ("used_including_cache_pct", "RAM usada incluyendo cache", "%"),
            ("used_without_buffer_cache_mib", "RAM usada sin buffers/cache", "MiB"),
            ("used_without_buffer_cache_pct", "RAM usada sin buffers/cache", "%"),
        ])

    rows = []

    for metric, label, unit in metric_defs:
        values = [to_float(row.get(metric)) for row in samples]
        st = basic_stats(values)

        rows.append({
            "metric": metric,
            "label": label,
            "unit": unit,
            "n": st["n"],
            "min": fmt(st["min"]),
            "mean": fmt(st["mean"]),
            "median": fmt(st["median"]),
            "p95": fmt(st["p95"]),
            "max": fmt(st["max"]),
            "std": fmt(st["std"]),
        })

    return rows


def parse_pidstat_memory(raw_dir):
    """
    Lee pidstat*.log y extrae RAM por proceso.
    Usa RSS como métrica principal porque representa memoria residente real.
    """
    process_values = {}

    for path in sorted(raw_dir.glob("pidstat*.log")):
        header = None
        in_memory_table = False

        for line in read_text(path).splitlines():
            parts = line.split()

            if not parts:
                continue

            if "Command" in parts:
                in_memory_table = {"VSZ", "RSS", "%MEM"}.issubset(set(parts))
                header = parts if in_memory_table else None
                continue

            if not in_memory_table or header is None:
                continue

            if "UID" in parts:
                continue

            is_average = parts[0] in AVG_TOKENS
            is_timestamp = re.match(r"^\d{1,2}:\d{2}:\d{2}$", parts[0]) is not None

            if not is_average and not is_timestamp:
                continue

            try:
                vsz_i = header.index("VSZ")
                rss_i = header.index("RSS")
                mem_i = header.index("%MEM")
                cmd_i = header.index("Command")
            except ValueError:
                continue

            if len(parts) <= cmd_i:
                continue

            vsz_kib = to_float(parts[vsz_i])
            rss_kib = to_float(parts[rss_i])
            mem_pct = to_float(parts[mem_i])
            command = " ".join(parts[cmd_i:]).strip()

            if not command:
                continue

            bucket = process_values.setdefault(command, {
                "process": command,
                "rss_mib": [],
                "vsz_mib": [],
                "mem_pct": [],
                "source_files": set(),
            })

            if rss_kib is not None:
                bucket["rss_mib"].append(rss_kib / 1024.0)

            if vsz_kib is not None:
                bucket["vsz_mib"].append(vsz_kib / 1024.0)

            if mem_pct is not None:
                bucket["mem_pct"].append(mem_pct)

            bucket["source_files"].add(path.name)

    rows = []

    for process, data in process_values.items():
        rss = data["rss_mib"]
        vsz = data["vsz_mib"]
        mem_pct = data["mem_pct"]

        if not rss:
            continue

        rows.append({
            "process": process,
            "avg_rss_mib": statistics.mean(rss),
            "max_rss_mib": max(rss),
            "avg_vsz_mib": statistics.mean(vsz) if vsz else "",
            "avg_mem_pct": statistics.mean(mem_pct) if mem_pct else "",
            "max_mem_pct": max(mem_pct) if mem_pct else "",
            "samples": max(len(rss), len(mem_pct)),
            "source_files": ";".join(sorted(data["source_files"])),
        })

    rows.sort(key=lambda r: r["avg_rss_mib"], reverse=True)

    cumulative = 0.0
    for idx, row in enumerate(rows, start=1):
        cumulative += row["avg_rss_mib"]
        row["rank"] = idx
        row["cumulative_rss_mib"] = cumulative

    return rows


def plot_total_ram_scenario(run_dir, samples):
    """
    Gráfica principal por escenario:
    consumo total de RAM en el tiempo.
    No compara escenarios entre sí.
    """
    if not samples:
        return None

    if "used_without_buffer_cache_mib" not in samples[0]:
        return None

    figures_dir = run_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    x = [row["elapsed_s"] for row in samples]

    used_no_cache = [row["used_without_buffer_cache_mib"] for row in samples]
    used_with_cache = [row["used_including_cache_mib"] for row in samples]
    swpd = [row["swpd_mib"] for row in samples]

    title = make_run_title(run_dir)

    fig, ax = plt.subplots(figsize=(11, 6.2))

    ax.plot(x, used_no_cache, label="RAM usada sin buffers/cache")
    ax.plot(x, used_with_cache, label="RAM usada incluyendo cache")
    ax.plot(x, swpd, label="Swap usada")

    ax.set_title(f"Consumo total de RAM del escenario\n{title}")
    ax.set_xlabel("Tiempo transcurrido [s]")
    ax.set_ylabel("Memoria [MiB]")
    ax.grid(True, linewidth=0.4, alpha=0.5)
    ax.legend(loc="best")
    fig.tight_layout()

    out_path = figures_dir / "ram_total_scenario_timeseries.png"
    fig.savefig(out_path, dpi=300)
    plt.close(fig)

    return out_path


def plot_ram_components(run_dir, samples):
    """
    Gráfica complementaria de componentes: libre, buffers, cache, swap.
    """
    if not samples:
        return None

    figures_dir = run_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    x = [row["elapsed_s"] for row in samples]

    free = [row["free_mib"] for row in samples]
    buff = [row["buff_mib"] for row in samples]
    cache = [row["cache_mib"] for row in samples]
    available = [row["available_proxy_mib"] for row in samples]
    swpd = [row["swpd_mib"] for row in samples]

    title = make_run_title(run_dir)

    fig, ax = plt.subplots(figsize=(11, 6.2))

    ax.plot(x, free, label="Memoria libre")
    ax.plot(x, buff, label="Buffers")
    ax.plot(x, cache, label="Cache")
    ax.plot(x, available, label="Libre + buffers + cache")
    ax.plot(x, swpd, label="Swap usada")

    ax.set_title(f"Componentes de memoria del escenario\n{title}")
    ax.set_xlabel("Tiempo transcurrido [s]")
    ax.set_ylabel("Memoria [MiB]")
    ax.grid(True, linewidth=0.4, alpha=0.5)
    ax.legend(loc="best")
    fig.tight_layout()

    out_path = figures_dir / "ram_components_timeseries.png"
    fig.savefig(out_path, dpi=300)
    plt.close(fig)

    return out_path


def plot_ram_process_cumulative(run_dir, process_rows, top_n=12):
    """
    Gráfica tipo CPU del HTML:
    barras por proceso y línea acumulada.
    """
    if not process_rows:
        return None

    figures_dir = run_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    rows = process_rows[:top_n]

    processes = []
    rss_values = []
    cumulative_values = []

    for row in rows:
        process_name = row["process"]
        if len(process_name) > 22:
            process_name = process_name[:19] + "..."

        processes.append(process_name)
        rss_values.append(row["avg_rss_mib"])
        cumulative_values.append(row["cumulative_rss_mib"])

    title = make_run_title(run_dir)

    fig, ax1 = plt.subplots(figsize=(12, 6.5))

    x = list(range(len(processes)))

    ax1.bar(x, rss_values, label="RSS promedio por proceso")
    ax1.set_xlabel("Proceso")
    ax1.set_ylabel("RSS promedio [MiB]")
    ax1.set_xticks(x)
    ax1.set_xticklabels(processes, rotation=35, ha="right")
    ax1.grid(True, axis="y", linewidth=0.4, alpha=0.5)

    ax2 = ax1.twinx()
    ax2.plot(x, cumulative_values, marker="o", label="RSS acumulado")
    ax2.set_ylabel("RSS acumulado [MiB]")

    ax1.set_title(f"RAM por proceso y acumulado\n{title}")

    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax2.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc="best")

    fig.tight_layout()

    out_path = figures_dir / "ram_process_cumulative.png"
    fig.savefig(out_path, dpi=300)
    plt.close(fig)

    return out_path


def write_process_csv(run_dir, process_rows):
    fields = [
        "rank",
        "process",
        "avg_rss_mib",
        "max_rss_mib",
        "avg_vsz_mib",
        "avg_mem_pct",
        "max_mem_pct",
        "cumulative_rss_mib",
        "samples",
        "source_files",
    ]

    formatted = []

    for row in process_rows:
        formatted.append({
            "rank": row.get("rank", ""),
            "process": row.get("process", ""),
            "avg_rss_mib": fmt(row.get("avg_rss_mib")),
            "max_rss_mib": fmt(row.get("max_rss_mib")),
            "avg_vsz_mib": fmt(row.get("avg_vsz_mib")),
            "avg_mem_pct": fmt(row.get("avg_mem_pct")),
            "max_mem_pct": fmt(row.get("max_mem_pct")),
            "cumulative_rss_mib": fmt(row.get("cumulative_rss_mib")),
            "samples": row.get("samples", ""),
            "source_files": row.get("source_files", ""),
        })

    write_csv(run_dir / "csv" / "ram_process_summary.csv", fields, formatted)


def process_run(run_dir, mem_total_kib=None, keep_first=False, top_n=12):
    raw_dir = run_dir / "raw"
    csv_dir = run_dir / "csv"
    figures_dir = run_dir / "figures"

    csv_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    vmstat_path = raw_dir / "vmstat.log"

    interval = infer_interval_seconds(run_dir)
    inferred_total = infer_mem_total_kib(run_dir)
    final_mem_total_kib = mem_total_kib or inferred_total

    samples = parse_vmstat(
        vmstat_path,
        interval_seconds=interval,
        mem_total_kib=final_mem_total_kib,
        keep_first=keep_first,
    )

    summary_rows = summarize_vmstat(samples)
    process_rows = parse_pidstat_memory(raw_dir)

    sample_fields = [
        "sample",
        "elapsed_s",
        "mem_total_mib",
        "swpd_mib",
        "free_mib",
        "buff_mib",
        "cache_mib",
        "available_proxy_mib",
        "used_including_cache_mib",
        "used_including_cache_pct",
        "used_without_buffer_cache_mib",
        "used_without_buffer_cache_pct",
        "swap_in_kib_s",
        "swap_out_kib_s",
        "context_switches_s",
        "cpu_user_pct",
        "cpu_system_pct",
        "cpu_idle_pct",
        "cpu_iowait_pct",
    ]

    write_csv(csv_dir / "ram_vmstat_samples.csv", sample_fields, samples)

    summary_fields = [
        "metric",
        "label",
        "unit",
        "n",
        "min",
        "mean",
        "median",
        "p95",
        "max",
        "std",
    ]

    write_csv(csv_dir / "ram_vmstat_summary.csv", summary_fields, summary_rows)
    write_process_csv(run_dir, process_rows)

    fig_total = plot_total_ram_scenario(run_dir, samples)
    fig_components = plot_ram_components(run_dir, samples)
    fig_process = plot_ram_process_cumulative(run_dir, process_rows, top_n=top_n)

    return {
        "run_id": run_dir.name,
        "scenario_label": infer_label(run_dir),
        "target": infer_target(run_dir),
        "iface": infer_iface(run_dir),
        "samples": len(samples),
        "processes": len(process_rows),
        "mem_total_mib": fmt(final_mem_total_kib / 1024.0) if final_mem_total_kib else "",
        "figure_total_ram": str(fig_total) if fig_total else "",
        "figure_components": str(fig_components) if fig_components else "",
        "figure_process_ram": str(fig_process) if fig_process else "",
        "run_path": str(run_dir),
    }


def copy_key_figures(root, run_summaries):
    out_dir = root / "ram_figures_all_runs" / "por_corrida"
    out_dir.mkdir(parents=True, exist_ok=True)

    copied = []

    for row in run_summaries:
        run_id = safe_filename(row["run_id"])

        for key, suffix in [
            ("figure_total_ram", "ram_total_scenario_timeseries.png"),
            ("figure_components", "ram_components_timeseries.png"),
            ("figure_process_ram", "ram_process_cumulative.png"),
        ]:
            src = row.get(key)
            if not src:
                continue

            src_path = Path(src)
            if not src_path.exists():
                continue

            dst = out_dir / f"{run_id}__{suffix}"
            dst.write_bytes(src_path.read_bytes())
            copied.append(dst)

    return copied


def main():
    parser = argparse.ArgumentParser(
        description="Genera gráficas individuales de RAM total por escenario y RAM por proceso acumulada desde vmstat.log y pidstat*.log."
    )

    parser.add_argument(
        "--root",
        required=True,
        help="Carpeta raíz. Puede ser Resultados FINALES completa o una corrida específica."
    )

    parser.add_argument(
        "--mem-total-mib",
        type=float,
        required=True,
        help="RAM total del host en MiB. Necesaria para graficar consumo total de RAM."
    )

    parser.add_argument(
        "--keep-first",
        action="store_true",
        help="No descarta la primera muestra de vmstat. Por defecto se descarta porque suele ser promedio desde arranque."
    )

    parser.add_argument(
        "--top-n",
        type=int,
        default=12,
        help="Cantidad de procesos a mostrar en la gráfica de RAM por proceso. Default: 12."
    )

    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        raise SystemExit(f"No existe la ruta: {root}")

    mem_total_kib = int(args.mem_total_mib * 1024)

    runs = find_runs(root)

    if not runs:
        raise SystemExit("No se encontró ningún raw/vmstat.log dentro de la ruta indicada.")

    print(f"[INFO] Corridas encontradas: {len(runs)}")

    run_summaries = []

    for run_dir in runs:
        print(f"\n[INFO] Procesando: {run_dir}")

        summary = process_run(
            run_dir=run_dir,
            mem_total_kib=mem_total_kib,
            keep_first=args.keep_first,
            top_n=args.top_n,
        )

        run_summaries.append(summary)

        print(f"[OK] CSV muestras RAM: {run_dir / 'csv' / 'ram_vmstat_samples.csv'}")
        print(f"[OK] CSV resumen RAM: {run_dir / 'csv' / 'ram_vmstat_summary.csv'}")
        print(f"[OK] CSV RAM por proceso: {run_dir / 'csv' / 'ram_process_summary.csv'}")
        print(f"[OK] Figura RAM total: {summary['figure_total_ram']}")
        print(f"[OK] Figura RAM por proceso: {summary['figure_process_ram']}")

    master_fields = [
        "run_id",
        "scenario_label",
        "target",
        "iface",
        "samples",
        "processes",
        "mem_total_mib",
        "figure_total_ram",
        "figure_components",
        "figure_process_ram",
        "run_path",
    ]

    master_csv = root / "ram_all_runs_index.csv"
    write_csv(master_csv, master_fields, run_summaries)

    copied = copy_key_figures(root, run_summaries)

    print("\n[OK] Procesamiento terminado.")
    print(f"[OK] Índice global: {master_csv}")
    print(f"[OK] Copia de figuras por corrida: {root / 'ram_figures_all_runs' / 'por_corrida'}")
    print(f"[OK] Figuras copiadas: {len(copied)}")


if __name__ == "__main__":
    main()