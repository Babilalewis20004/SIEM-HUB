"""
Run with: python seed.py
Creates default detection rules and a handful of sample events so the
dashboard isn't empty on first run.
"""
from datetime import datetime, timedelta
import random

from app import create_app, db
from app.models import Rule, Event, User
from app.models.mitre import MitreTechnique
from app.playbooks.models import Playbook
from app.services.ml_detection import train_model

app = create_app()

with app.app_context():
    # --- MITRE ATT&CK catalogue + mapping ---
    # Only techniques that map to a detection this project actually ships.
    # T1110 (Brute Force / Credential Access) matches brute_force_ssh's
    # semantics exactly -- repeated failed authentication attempts.
    # http_error_burst (web error volume) and the off-hours/ML heuristics
    # get no mapping: none of them are a clean, justified match for any
    # single ATT&CK technique, and inventing one would mislead an analyst.
    t1110 = MitreTechnique.query.filter_by(technique_id="T1110").first()
    if not t1110:
        t1110 = MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic="Credential Access",
            description="Adversaries may use brute force techniques to gain access to accounts "
                        "when passwords are unknown or when password hashes are obtained.",
            url="https://attack.mitre.org/techniques/T1110/",
        )
        db.session.add(t1110)
        db.session.commit()

    # --- Sample IOC ---
    # Matches the source IP of the brute-force burst seeded below, so a
    # fresh `python seed.py` + a detection run produces a fully enriched
    # demo alert/incident (MITRE T1110 + IOC match) out of the box.
    from app.models.ioc import IOC
    if not IOC.query.filter_by(indicator_type="ip", normalized_indicator="203.0.113.5").first():
        db.session.add(IOC(
            indicator="203.0.113.5",
            indicator_type="ip",
            normalized_indicator="203.0.113.5",
            threat_level="high",
            confidence=92,
            source="internal",
            description="Known brute-force source (demo data).",
        ))
        db.session.commit()

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
    brute_force_rule = Rule.query.filter_by(name="brute_force_ssh").first()
    if not brute_force_rule:
        brute_force_rule = Rule(
            name="brute_force_ssh",
            rule_type="threshold",
            condition={
                "event_type": "authentication_failure",
                "count": 5,
                "window_seconds": 60,
                "group_by": "source_ip",
            },
            severity="critical",
        )
        db.session.add(brute_force_rule)
    # Backfill the MITRE mapping even onto a rule that already existed from
    # before this catalogue was added, so re-running seed.py on an older DB
    # still ends up fully mapped.
    if t1110 not in brute_force_rule.mitre_techniques:
        brute_force_rule.mitre_tactic = t1110.tactic
        brute_force_rule.mitre_technique = t1110.technique_id
        brute_force_rule.mitre_techniques = [t1110]

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

    # --- Default playbooks (Part Y demonstration set) ---
    # All three are deliberately non-destructive: block_ip only ever reaches
    # MockResponseProvider (see app/playbooks/providers.py), never a real
    # network device, and every step is a registered action (see
    # app/playbooks/registry.py) -- no arbitrary code in `steps`.
    _default_playbooks = [
        {
            "name": "SSH Brute Force Response",
            "description": "Tags and annotates the incident when the brute_force_ssh rule fires. "
                            "No external/destructive action -- investigation aid only.",
            "trigger_type": "alert",
            "trigger_condition": {"rule_name": "brute_force_ssh"},
            "steps": [
                {"action": "add_incident_tag", "parameters": {"tag": "brute-force"}},
                {"action": "create_case_note",
                 "parameters": {"content": "Automated brute-force response initiated by playbook."}},
                {"action": "notify_analyst", "parameters": {"message": "SSH brute-force detected."}},
            ],
        },
        {
            "name": "Malicious IOC Investigation",
            "description": "Tags and annotates the incident on a high-confidence IOC match, then "
                            "requests approval to block the source IP (simulated -- MockResponseProvider).",
            "trigger_type": "alert",
            "trigger_condition": {"ioc_match": True},
            "steps": [
                {"action": "add_incident_tag", "parameters": {"tag": "malicious-ioc"}},
                {"action": "create_case_note",
                 "parameters": {"content": "Alert matched a known-malicious indicator of compromise."}},
                {"action": "notify_analyst", "parameters": {"message": "Malicious IOC match -- review recommended."}},
                {"action": "block_ip", "parameters": {"ip": "{{source_ip}}"}},
            ],
        },
        {
            "name": "Critical Incident Notification",
            "description": "Notifies the SOC and adds an investigation note whenever an incident's "
                            "severity reaches critical.",
            "trigger_type": "incident",
            "trigger_condition": {"severity": "critical"},
            "steps": [
                {"action": "notify_analyst", "parameters": {"message": "Critical incident opened."}},
                {"action": "create_case_note",
                 "parameters": {"content": "Incident automatically flagged as critical severity."}},
            ],
        },
    ]
    for pb in _default_playbooks:
        if not Playbook.query.filter_by(name=pb["name"]).first():
            db.session.add(Playbook(**pb))
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
