#!/usr/bin/env bash
set -euo pipefail

echo "[trivy-host-scanner] starting. interval=${SCAN_INTERVAL_SECONDS}s target=${TARGET_DIR} output=${OUTPUT_DIR}"

# Run once immediately on boot, then on a loop, so node-exporter always has
# fresh data shortly after `docker compose up` instead of waiting a full cycle.
while true; do
  echo "[trivy-host-scanner] $(date -u +%FT%TZ) - scan starting"
  python3 /app/scan.py || echo "[trivy-host-scanner] scan failed, will retry next cycle"
  echo "[trivy-host-scanner] $(date -u +%FT%TZ) - scan complete, sleeping ${SCAN_INTERVAL_SECONDS}s"
  sleep "${SCAN_INTERVAL_SECONDS}"
done
