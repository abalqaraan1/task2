# Full-Stack Observability & Security Monitoring Stack

A local, production-shaped monitoring stack with three lanes:

| Lane      | Components                                   | Purpose                                  |
|-----------|-----------------------------------------------|-------------------------------------------|
| Metrics   | Prometheus, Node-exporter, cAdvisor           | Time-series metrics for host + containers |
| Logs      | Vector, Loki, Grafana                         | Centralized log aggregation & search      |
| Security  | Trivy Host Scanner, Trivy Watcher (custom)    | Continuous vulnerability scanning         |

```
monitoring-stack/
├── docker-compose.yml
├── config/
│   ├── prometheus/prometheus.yml
│   ├── loki/loki-config.yml
│   ├── vector/vector.toml
│   └── grafana/provisioning/datasources/datasources.yml
├── trivy-host-scanner/     # scans /host on a timer -> node-exporter textfile
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── scan.py
└── trivy-watcher/          # watches docker socket -> scans new containers
    ├── Dockerfile
    ├── requirements.txt
    └── watcher.py
```

## Ports

| Service            | Port  | What it's for                        |
|---------------------|-------|----------------------------------------|
| Grafana             | 9000  | Dashboards / UI                        |
| Prometheus          | 9090  | Metrics query UI + API                 |
| Loki                | 3100  | Log query API (used via Grafana)       |
| Node-exporter       | 9100  | Host metrics + Trivy host-scan metrics |
| cAdvisor             | 8085  | Per-container resource metrics         |
| Trivy Watcher (API)  | 8090  | JSON: `/containers`, `/healthz`        |
| Trivy Watcher (metrics) | 8086 | Prometheus `/metrics` endpoint      |

## Step 1: Prerequisites

- Docker Engine + Docker Compose v2 (`docker compose version`)
- Linux/macOS host (the `/var/run/docker.sock` and `/:/host:ro` mounts assume a
  Unix-style Docker socket; on Docker Desktop for Mac/Windows the socket path
  is proxied automatically, but the "host filesystem" the Trivy scanner sees
  will be the VM's filesystem, not your literal machine).

## Step 2: Build & start the stack

```bash
cd monitoring-stack
docker compose build          # builds trivy-host-scanner and trivy-watcher images
docker compose up -d
docker compose ps             # confirm all 8 services are "Up"
```

First boot will take a minute or two: Trivy downloads its vulnerability
database (~cached in the `trivy_cache` volume for subsequent scans), and the
`trivy-watcher` primes itself by scanning every already-running container.

## Step 3: Verify each lane

**Metrics** — Prometheus targets should all show "UP":
```
http://localhost:9090/targets
```

**Logs** — check Vector is shipping and Loki is receiving:
```bash
docker compose logs vector --tail=20
curl -s "http://localhost:3100/loki/api/v1/labels" | jq
```
You should see label keys like `container`, `image`, `stream`, `job` — and
critically, **no** `vector`, `loki`, `grafana`, `prometheus`, `node-exporter`,
`cadvisor`, `trivy-host-scanner`, or `trivy-watcher` values under `container`,
confirming the exclusion filter worked.

**Security** — host scan output feeding node-exporter's textfile collector:
```bash
curl -s http://localhost:9100/metrics | grep trivy_host
```
Container watcher JSON + Prometheus outputs:
```bash
curl -s http://localhost:8090/containers | jq
curl -s http://localhost:8086/metrics | grep trivy_watcher
```

## Step 4: Log into Grafana

```
URL:      http://localhost:9000
Username: admin
Password: admin   (you'll be prompted to change it on first login)
```

## Step 5: Wire up Data Sources (manual, per the task requirement)

The compose file ships an *optional* provisioning file
(`config/grafana/provisioning/datasources/datasources.yml`) that will
auto-register both sources on boot. To do it manually through the UI instead
(or to double check the provisioned ones):

1. In Grafana, go to **Connections → Data sources → Add data source**.
2. Choose **Prometheus**.
   - URL: `http://prometheus:9090` (container-to-container DNS name — not
     `localhost`, since Grafana calls it from inside the Docker network)
   - Click **Save & test** — expect "Successfully queried the Prometheus API".
   - Optionally toggle **Default** on.
3. Go back to **Add data source**, choose **Loki**.
   - URL: `http://loki:3100`
   - Click **Save & test** — expect "Data source connected and labels found".
4. Confirm both appear under **Connections → Data sources** and that
   **Explore** (left nav) lets you query both — PromQL against Prometheus,
   LogQL against Loki.

> If you want a completely from-scratch manual walkthrough, delete or rename
> `config/grafana/provisioning/datasources/datasources.yml` before
> `docker compose up` so nothing is pre-registered.

## How each requirement is satisfied

- **Scaffolding**: `docker-compose.yml` at the root, `config/` for all app
  settings, `trivy-host-scanner/` and `trivy-watcher/` as independent build
  contexts.
- **Log filtering**: `vector.toml`'s `docker_logs` source uses
  `exclude_containers` to drop the 8 monitoring-stack container names,
  preventing the log-loop the task warns about. Timestamps are normalized to
  a real `timestamp` type in the `remap` transform before being JSON-encoded
  and shipped to the Loki sink.
- **Host scanning "trick"**: `trivy-host-scanner` loops on
  `SCAN_INTERVAL_SECONDS`, runs `trivy fs /host`, and writes a
  Prometheus-textfile-formatted `.prom` file into a **volume shared with
  node-exporter**, which is configured with
  `--collector.textfile.directory=/textfile_collector` so it automatically
  ingests those metrics on its next scrape — no separate exporter needed.
- **Container watcher**: `trivy-watcher` opens a live stream from
  `client.events(filters={"event": "start"})` on the Docker socket. Each new
  container triggers a background `trivy image` scan; results land in an
  in-memory store served two ways — a Flask JSON API on 8090 and
  `prometheus_client` gauges scraped by Prometheus on 8086.

## Tearing down

```bash
docker compose down            # stop + remove containers
docker compose down -v         # also wipe Prometheus/Loki/Grafana/Trivy data
```

## Customizing scan frequency

Edit `SCAN_INTERVAL_SECONDS` under `trivy-host-scanner` in
`docker-compose.yml` (default: `21600` = 6 hours), then
`docker compose up -d --build trivy-host-scanner`.
