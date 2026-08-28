"""
Run with: python seed.py
Creates default detection rules and a handful of sample events so the
dashboard isn't empty on first run.
"""
from datetime import datetime, timedelta
import random

from app import create_app, db
from app.models import Rule, Event, User
from app.services.ml_detection import train_model

app = create_app()

with app.app_context():
    # --- Default admin user (dev convenience — change this password immediately) ---
    DEFAULT_ADMIN_EMAIL = "admin@example.com"
    DEFAULT_ADMIN_PASSWORD = "changeme123"
    if not User.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first():
        admin = User(email=DEFAULT_ADMIN_EMAIL, role="admin")
        admin.set_password(DEFAULT_ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print(f"Created default admin user: {DEFAULT_ADMIN_EMAIL} / {DEFAULT_ADMIN_PASSWORD}")
        print("  -> Log in with these, then change the password (or delete this user and register your own).")

    # --- Default rules ---
    if not Rule.query.filter_by(name="brute_force_ssh").first():
        db.session.add(Rule(
            name="brute_force_ssh",
            rule_type="threshold",
            condition={
                "event_type": "authentication_failure",
                "count": 5,
                "window_seconds": 60,
                "group_by": "source_ip",
            },
            severity="critical",
        ))

    if not Rule.query.filter_by(name="http_error_burst").first():
        db.session.add(Rule(
            name="http_error_burst",
            rule_type="threshold",
            condition={
                "category": "web",
                "count": 20,
                "window_seconds": 60,
                "group_by": "source_ip",
            },
            severity="warning",
        ))

    db.session.commit()

    # --- Sample events (only if DB is empty) ---
    if Event.query.count() == 0:
        now = datetime.utcnow()
        sample_ips = ["203.0.113.5", "198.51.100.23", "10.0.0.15"]

        # A brute-force burst from one IP
        for i in range(7):
            db.session.add(Event(
                timestamp=now - timedelta(seconds=i * 5),
                event_type="authentication_failure",
                category="authentication",
                source_type="ssh",
                source_ip="203.0.113.5",
                destination_port=22,
                username="admin",
                hostname="web01",
                action="login",
                outcome="failure",
                severity="medium",
                raw_message=f"sshd: Failed password for invalid user admin from 203.0.113.5 port {50000+i} ssh2",
                parsed_fields={"pid": None, "protocol": "ssh2"},
            ))

        # Normal traffic
        for i in range(30):
            ip = random.choice(sample_ips)
            status = random.choice([200, 200, 200, 404, 500])
            is_error = status >= 400
            db.session.add(Event(
                timestamp=now - timedelta(minutes=i),
                event_type="http_error" if is_error else "http_request",
                category="web",
                source_type="nginx",
                source_ip=ip,
                destination_port=80,
                hostname="web01",
                action="request",
                outcome="failure" if is_error else "success",
                severity="high" if status >= 500 else ("low" if is_error else "info"),
                raw_message=f'{ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /index HTTP/1.1" {status} 512',
                parsed_fields={"method": "GET", "path": "/index", "status_code": status, "response_bytes": 512},
            ))

        # Spread-out "normal" baseline traffic across several hours/IPs so the
        # Isolation Forest has enough (source_ip, time-bucket) samples to train on.
        baseline_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        for minute_offset in range(180, 0, -1):
            ts_base = now - timedelta(minutes=minute_offset)
            for ip in baseline_ips:
                for i in range(random.randint(1, 4)):
                    status = random.choice([200, 200, 200, 200, 404])
                    is_error = status >= 400
                    db.session.add(Event(
                        timestamp=ts_base + timedelta(seconds=i * 10),
                        event_type="http_error" if is_error else "http_request",
                        category="web",
                        source_type="nginx",
                        source_ip=ip,
                        destination_port=80,
                        hostname="web01",
                        action="request",
                        outcome="failure" if is_error else "success",
                        severity="low" if is_error else "info",
                        raw_message=f"{ip} baseline request {status}",
                        parsed_fields={"method": "GET", "path": "/home", "status_code": status,
                                       "response_bytes": random.randint(200, 800)},
                    ))

        db.session.commit()

        # Train the Isolation Forest on the baseline traffic we just created.
        result = train_model()
        if result.get("trained"):
            print(f"ML model trained on {result['training_samples']} activity buckets.")
        else:
            print(f"ML model not trained: {result.get('reason')}")

    print("Seed complete.")
