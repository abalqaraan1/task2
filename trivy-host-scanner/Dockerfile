# Pull the trivy binary straight from Aqua's official image instead of the
# curl|sh install script -- avoids GitHub API rate limits / transient
# download failures and any glibc-vs-musl binary mismatch on Alpine.
ARG TRIVY_VERSION=0.55.2
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.12-alpine

RUN apk add --no-cache bash ca-certificates

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY scan.py /app/scan.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV SCAN_INTERVAL_SECONDS=21600 \
    OUTPUT_DIR=/output \
    TARGET_DIR=/host

ENTRYPOINT ["/app/entrypoint.sh"]
