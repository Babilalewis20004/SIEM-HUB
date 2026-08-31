"""
Prometheus metrics registered at import time (the client library's
standard pattern -- a Counter/Histogram is a module-level singleton backed
by the default CollectorRegistry). Scraped by the optional Prometheus +
Grafana stack in observability/docker-compose.yml (see
docs/ARCHITECTURE.md's Observability section) -- run it if you want
dashboards, but /metrics works standalone either way.
"""
from prometheus_client import Counter, Histogram

http_requests_total = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "path", "status"]
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds", "HTTP request duration in seconds", ["method", "path"]
)

# Label is "job_name", not "job": Prometheus's scrape config already injects
# a "job" label on every series (from prometheus.yml's job_name) and
# silently renames a same-named metric label to "exported_job" rather than
# erroring, so "job" here would merge every job into one series in Grafana
# instead of erroring loudly.
detection_job_runs_total = Counter(
    "detection_job_runs_total", "Total scheduled detection job runs", ["job_name", "outcome"]
)
detection_job_duration_seconds = Histogram(
    "detection_job_duration_seconds", "Scheduled detection job duration in seconds", ["job_name"]
)

alerts_created_total = Counter(
    "alerts_created_total", "Total alerts created", ["detection_source", "severity"]
)

playbook_executions_total = Counter(
    "playbook_executions_total", "Total playbook executions", ["outcome"]
)
