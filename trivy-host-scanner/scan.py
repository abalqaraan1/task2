#!/usr/bin/env python3
"""
Runs `trivy fs` against the mounted host filesystem (/host) and converts the
JSON vulnerability report into a Prometheus node-exporter textfile-collector
(.prom) file. Written atomically (tmp file + rename) since node-exporter's
textfile collector requires the file to never be observed in a half-written
state.
"""
import json
import os
import subprocess
import sys
import time

TARGET_DIR = os.environ.get("TARGET_DIR", "/host")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/output")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "trivy_host_scan.prom")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Directories that are either virtual, huge, or not meaningful to scan for
# package vulnerabilities when the whole host root is mounted read-only.
SKIP_DIRS = [
    "/host/proc", "/host/sys", "/host/dev", "/host/run",
    "/host/var/lib/docker", "/host/var/lib/containerd",
    "/host/mnt", "/host/tmp", "/host/output",
]


def run_trivy():
    cmd = [
        "trivy", "fs",
        "--scanners", "vuln",
        "--format", "json",
        "--quiet",
        "--timeout", "10m",
    ]
    for d in SKIP_DIRS:
        cmd += ["--skip-dirs", d]
    cmd.append(TARGET_DIR)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if result.returncode not in (0,):
        sys.stderr.write(f"trivy exited {result.returncode}: {result.stderr[-2000:]}\n")
    if not result.stdout.strip():
        raise RuntimeError("trivy produced no output")
    return json.loads(result.stdout)


def count_vulnerabilities(report):
    counts = {sev: 0 for sev in SEVERITIES}
    for res in report.get("Results", []) or []:
        for vuln in res.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def write_prom_file(counts, scan_duration_s, scan_ok=1):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tmp_path = OUTPUT_FILE + ".tmp"

    lines = [
        "# HELP trivy_host_vulnerabilities_total Vulnerabilities found on the host filesystem by severity",
        "# TYPE trivy_host_vulnerabilities_total gauge",
    ]
    for sev, count in counts.items():
        lines.append(f'trivy_host_vulnerabilities_total{{severity="{sev}"}} {count}')

    lines += [
        "# HELP trivy_host_scan_duration_seconds Duration of the last host filesystem scan",
        "# TYPE trivy_host_scan_duration_seconds gauge",
        f"trivy_host_scan_duration_seconds {scan_duration_s:.2f}",
        "# HELP trivy_host_scan_timestamp_seconds Unix timestamp of the last completed host scan",
        "# TYPE trivy_host_scan_timestamp_seconds gauge",
        f"trivy_host_scan_timestamp_seconds {int(time.time())}",
        "# HELP trivy_host_scan_success Whether the last scan completed successfully (1) or failed (0)",
        "# TYPE trivy_host_scan_success gauge",
        f"trivy_host_scan_success {scan_ok}",
        "",  # trailing newline
    ]

    with open(tmp_path, "w") as f:
        f.write("\n".join(lines))
    os.replace(tmp_path, OUTPUT_FILE)  # atomic on POSIX


def main():
    start = time.time()
    try:
        report = run_trivy()
        counts = count_vulnerabilities(report)
        write_prom_file(counts, time.time() - start, scan_ok=1)
        print(f"[scan.py] wrote {OUTPUT_FILE}: {counts}")
    except Exception as e:
        # Still emit a metrics file so trivy_host_scan_success flips to 0
        # and alerts on scan failures instead of just silently going stale.
        write_prom_file({sev: 0 for sev in SEVERITIES}, time.time() - start, scan_ok=0)
        print(f"[scan.py] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
