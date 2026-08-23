# Pull the trivy binary straight from Aqua's official image instead of the
# curl|sh install script -- avoids GitHub API rate limits / transient
# download failures and any glibc-vs-musl binary mismatch.
ARG TRIVY_VERSION=0.55.2
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY watcher.py .

EXPOSE 8090 8086

CMD ["python", "watcher.py"]
