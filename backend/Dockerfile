FROM python:3.12-slim

WORKDIR /app

# curl is only for the HEALTHCHECK below -- scikit-learn/numpy ship manylinux
# wheels for this base image so no compiler toolchain is needed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x docker-entrypoint.sh

ENV FLASK_APP=run.py \
    FLASK_DEBUG=false \
    PYTHONUNBUFFERED=1

EXPOSE 5000

# /data and app/ml_models are where docker-compose.yml's named volumes
# (siem-db, ml-models) get mounted -- pre-creating and chowning them here
# means Docker seeds the volumes with these permissions on first mount,
# instead of the non-root user below hitting a read-only root-owned dir.
RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app \
    && mkdir -p /data /app/app/ml_models \
    && chown -R app:app /app /data
USER app

# /api/health is the liveness check (app/routes/health.py) -- no DB
# dependency, so it won't false-fail while siem.db is just slow to open.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
