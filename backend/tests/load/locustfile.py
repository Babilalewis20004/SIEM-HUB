"""
Load test against a running instance (Docker or `python run.py`) -- NOT
part of the pytest suite or CI. See docs/PERFORMANCE.md for how this was
run and the measured results.

    pip install -r tests/load/requirements.txt
    locust -f tests/load/locustfile.py --host http://localhost:8080 \
        --headless -u 20 -r 5 -t 60s --csv=results

A note on login: every simulated user shares ONE token fetched once at
test start (below), not a fresh `/api/auth/login` per user. Logging in
concurrently at load-test volume immediately hits `RATELIMIT_LOGIN` (10/min
per IP, see docs/SECURITY.md) -- correctly, since real analysts don't all
log in simultaneously from one IP, and a first attempt at this test proved
that by producing ~50% 401s that were really the rate limiter doing its
job, not the app under real API load. This test measures the thing an
analyst's dashboard actually stresses: read-heavy API throughput on an
authenticated session, plus an occasional log upload -- weighted so reads
dominate, matching real SOC usage (many analysts watching, comparatively
few log sources pushing at once).
"""
import random
from datetime import datetime, timezone

from locust import HttpUser, task, between, events

_shared_token = {"value": None}


@events.test_start.add_listener
def _login_once(environment, **kwargs):
    import requests

    resp = requests.post(
        f"{environment.host}/api/auth/login",
        json={"email": "admin@example.com", "password": "changeme123"},
        timeout=10,
    )
    resp.raise_for_status()
    _shared_token["value"] = resp.json()["token"]


class AnalystUser(HttpUser):
    wait_time = between(0.5, 2.0)

    def on_start(self):
        self.headers = {"Authorization": f"Bearer {_shared_token['value']}"}

    @task(10)
    def list_alerts(self):
        self.client.get("/api/alerts?per_page=25", headers=self.headers, name="/api/alerts")

    @task(8)
    def dashboard_summary(self):
        self.client.get("/api/stats/summary", headers=self.headers, name="/api/stats/summary")

    @task(6)
    def list_logs_filtered(self):
        self.client.get(
            "/api/logs?category=authentication&per_page=25",
            headers=self.headers,
            name="/api/logs?filtered",
        )

    @task(3)
    def list_incidents(self):
        self.client.get("/api/incidents?per_page=25", headers=self.headers, name="/api/incidents")

    @task(1)
    def upload_log(self):
        ip = f"198.51.100.{random.randint(1, 254)}"
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "")
        self.client.post(
            "/api/logs/upload",
            headers=self.headers,
            json={
                "source": "nginx",
                "host": "loadtest",
                "lines": [
                    f'{ip} - - [{ts}] "GET /health HTTP/1.1" 200 512 "-" "locust"'
                ],
            },
            name="/api/logs/upload",
        )
