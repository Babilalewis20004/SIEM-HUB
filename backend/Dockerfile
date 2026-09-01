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

# /api/health is the liveness check (app/routes/health.py) -- no DB
# dependency, so it won't false-fail while siem.db is just slow to open.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
