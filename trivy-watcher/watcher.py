#!/usr/bin/env python3
"""
trivy-watcher
=============
Listens to the Docker socket for container "start" events. Whenever a new
container starts, it triggers a `trivy image` vulnerability scan against
that container's image in a background thread, then makes the results
available two ways:

  * JSON API      -> GET http://localhost:8090/containers
                     GET http://localhost:8090/containers/<id>
                     GET http://localhost:8090/healthz
  * Prometheus    -> GET http://localhost:8086/metrics
"""
import json
import logging
import subprocess
import threading
import time
from collections import defaultdict

import docker
from flask import Flask, jsonify
from prometheus_client import Gauge, start_http_server

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("trivy-watcher")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SCAN_TIMEOUT_S = 600

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_results: dict[str, dict] = {}   # container_id -> scan result payload

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
vuln_gauge = Gauge(
    "trivy_watcher_vulnerabilities",
    "Vulnerabilities found in a running container's image, by severity",
    ["container_name", "image", "severity"],
)
scan_success_gauge = Gauge(
    "trivy_watcher_scan_success",
    "1 if the most recent scan of this container succeeded, else 0",
    ["container_name", "image"],
)
scan_duration_gauge = Gauge(
    "trivy_watcher_scan_duration_seconds",
    "How long the most recent scan of this container took",
    ["container_name", "image"],
)
containers_watched_gauge = Gauge(
    "trivy_watcher_containers_watched",
    "Number of containers currently tracked by the watcher",
)


def scan_image(image_ref: str) -> dict:
    """Run `trivy image` against a local image ref and return severity counts."""
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--quiet",
        "--timeout", "8m",
        "--scanners", "vuln",
        image_ref,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_S)
    if result.returncode != 0:
        raise RuntimeError(f"trivy exited {result.returncode}: {result.stderr[-1500:]}")

    report = json.loads(result.stdout)
    counts = defaultdict(int)
    for res in report.get("Results", []) or []:
        for vuln in res.get("Vulnerabilities", []) or []:
            counts[vuln.get("Severity", "UNKNOWN").upper()] += 1
    return dict(counts)


def handle_new_container(container_id: str, container_name: str, image_ref: str):
    log.info("scanning new container %s (%s) image=%s", container_name, container_id[:12], image_ref)
    start = time.time()
    try:
        counts = scan_image(image_ref)
        duration = time.time() - start

        for sev in SEVERITIES:
            vuln_gauge.labels(container_name=container_name, image=image_ref, severity=sev).set(counts.get(sev, 0))
        scan_success_gauge.labels(container_name=container_name, image=image_ref).set(1)
        scan_duration_gauge.labels(container_name=container_name, image=image_ref).set(duration)

        with _lock:
            _results[container_id] = {
                "container_id": container_id,
                "container_name": container_name,
                "image": image_ref,
                "vulnerabilities": {sev: counts.get(sev, 0) for sev in SEVERITIES},
                "scan_duration_seconds": round(duration, 2),
                "scanned_at": int(time.time()),
                "status": "ok",
            }
            containers_watched_gauge.set(len(_results))
        log.info("scan complete for %s: %s", container_name, counts)

    except Exception as e:
        duration = time.time() - start
        scan_success_gauge.labels(container_name=container_name, image=image_ref).set(0)
        with _lock:
            _results[container_id] = {
                "container_id": container_id,
                "container_name": container_name,
                "image": image_ref,
                "error": str(e),
                "scan_duration_seconds": round(duration, 2),
                "scanned_at": int(time.time()),
                "status": "error",
            }
            containers_watched_gauge.set(len(_results))
        log.error("scan failed for %s: %s", container_name, e)


def scan_existing_containers(client: docker.DockerClient):
    """Prime the watcher with everything already running when it boots."""
    for container in client.containers.list():
        try:
            image_ref = (container.image.tags[0] if container.image.tags else container.image.short_id)
            threading.Thread(
                target=handle_new_container,
                args=(container.id, container.name, image_ref),
                daemon=True,
            ).start()
        except Exception as e:
            log.warning("could not queue existing container %s: %s", container.name, e)


def watch_docker_events(client: docker.DockerClient):
    log.info("listening for docker 'start' events...")
    for event in client.events(decode=True, filters={"type": "container", "event": "start"}):
        try:
            container_id = event["id"]
            container = client.containers.get(container_id)
            image_ref = (container.image.tags[0] if container.image.tags else container.image.short_id)
            threading.Thread(
                target=handle_new_container,
                args=(container_id, container.name, image_ref),
                daemon=True,
            ).start()
        except Exception as e:
            log.warning("failed to process docker event: %s", e)


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.get("/containers")
def list_containers():
    with _lock:
        return jsonify(list(_results.values()))


@app.get("/containers/<container_id>")
def get_container(container_id):
    with _lock:
        match = _results.get(container_id) or next(
            (v for k, v in _results.items() if k.startswith(container_id)), None
        )
    if not match:
        return jsonify({"error": "not found"}), 404
    return jsonify(match)


def main():
    client = docker.from_env()

    # Prometheus metrics server (port 8086)
    start_http_server(8086)
    log.info("prometheus metrics exposed on :8086/metrics")

    # Prime with already-running containers, then watch for new ones
    scan_existing_containers(client)
    threading.Thread(target=watch_docker_events, args=(client,), daemon=True).start()

    # JSON API (port 8090) -- runs in the main thread
    app.run(host="0.0.0.0", port=8090)


if __name__ == "__main__":
    main()
