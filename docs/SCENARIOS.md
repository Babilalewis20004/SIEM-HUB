# Example detection scenarios

Three walkthroughs, run for real against a live `docker compose` stack
seeded with `seed.py` (see the [Quick Start](../README.md#quick-start)).
Every request/response below is actual output captured from that run —
IDs, timestamps, and scores included — not hypothetical.

## 1. SSH brute force → MITRE → correlation → automated response

**Raw input** — 7 failed-login lines for one source IP, uploaded as if a
log shipper had forwarded them:

```bash
curl -X POST http://localhost:8080/api/logs/upload \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "source": "ssh", "host": "bastion01",
    "lines": [
      "2026-09-02T14:01:56 bastion01 sshd[2000]: Failed password for admin from 198.51.100.23 port 45000 ssh2",
      "2026-09-02T14:01:57 bastion01 sshd[2001]: Failed password for admin from 198.51.100.23 port 45001 ssh2",
      "2026-09-02T14:01:58 bastion01 sshd[2002]: Failed password for admin from 198.51.100.23 port 45002 ssh2",
      "2026-09-02T14:01:59 bastion01 sshd[2003]: Failed password for admin from 198.51.100.23 port 45003 ssh2",
      "2026-09-02T14:02:00 bastion01 sshd[2004]: Failed password for admin from 198.51.100.23 port 45004 ssh2",
      "2026-09-02T14:02:01 bastion01 sshd[2005]: Failed password for admin from 198.51.100.23 port 45005 ssh2",
      "2026-09-02T14:02:02 bastion01 sshd[2006]: Failed password for admin from 198.51.100.23 port 45006 ssh2"
    ]
  }'
```

```json
{"failed":0,"ingested":7,"normalised":7,"parsed":7,"stored":7,"total_lines":7}
```

All 7 lines parsed and normalised — one malformed line would never have
failed the batch (see `ARCHITECTURE.md`).

**Detection** (`POST /api/alerts/run-detection`, or the scheduler firing on
its own 30s interval) matches the `brute_force_ssh` threshold rule
(5+ `authentication_failure` events from one `source_ip` in 60s — 7 arrived,
threshold cleared):

```json
{
  "rule_name": "brute_force_ssh",
  "severity": "critical",
  "description": "brute_force_ssh: 7 matching events from '198.51.100.23' in 60s (threshold 5)",
  "mitre": [{"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
  "risk": {"overall_risk": "critical", "overall_score": 100},
  "context": {
    "correlation": {
      "score": 60,
      "reasons": ["same source IP (198.51.100.23)", "occurred within 15 minutes"]
    }
  }
}
```

The rule's `T1110` MITRE mapping was copied onto the alert automatically
(`app/services/mitre_enrichment.py`), and the correlation engine attached it
to an existing Incident on `198.51.100.23` rather than opening a new one
(score 60 ≥ the 50-point threshold).

**Automated response**: the *SSH Brute Force Response* playbook
(seeded by `seed.py`) triggered on `alert.created` for this exact rule,
tagged the incident, added an investigation note, and notified — all
low-risk, so it ran to completion automatically with no human step:

```json
{
  "playbook_name": "SSH Brute Force Response",
  "mode": "automatic",
  "status": "completed",
  "current_step_index": 3
}
```

## 2. ML anomaly detection catches what no rule was written for

The Isolation Forest model (trained on ~3 hours of seeded baseline traffic,
751 activity buckets) scores every completed 60-second `(source_ip,
window)` bucket independently of the rule engine — it flagged the very
same brute-force traffic above *before* it was even large enough to clear
the rule's 5-event threshold, because the *shape* of the traffic (all
failed logins, off-baseline event mix) was already unusual at 4 events:

```json
{
  "detection_source": "ml",
  "rule_name": "ml_isolation_forest",
  "title": "ML anomaly detected",
  "description": "Isolation Forest flagged unusual activity from 198.51.100.23: 4 events in 60s (anomaly score -0.117, lower = more anomalous)",
  "context": {
    "features": {
      "total_events": 4, "failed_logins": 4, "distinct_event_types": 1,
      "unique_users": 1, "is_off_hours": 0
    }
  },
  "risk": {"overall_risk": "medium", "overall_score": 50}
}
```

This is the point of running both engines: the threshold rule is precise
but only catches what it was explicitly written for; the ML layer has no
concept of "brute force" at all, it just knows this traffic *shape* doesn't
look like the baseline it trained on — so it would just as readily flag an
attack pattern nobody wrote a rule for yet.

## 3. IOC match → risk scoring → human-approved response

The seeded IOC table already contains a known-malicious indicator:

```json
{
  "indicator": "203.0.113.5", "indicator_type": "ip",
  "threat_level": "high", "confidence": 92,
  "source": "internal", "description": "Known brute-force source (demo data)."
}
```

When seeded sample traffic from that exact IP produced a `brute_force_ssh`
alert, `app/services/ioc_matching.py` matched the alert's `source_ip`
against the IOC table (one bulk query, not one lookup per indicator) and
`app/services/risk_scoring.py` blended the alert's own severity with the
IOC's `threat_level` into an `overall_risk` of **critical**.

That match also triggered the *Malicious IOC Investigation* playbook. Its
first two steps are low-risk and ran immediately:

```json
[
  {"action": "create_case_note", "status": "completed",
   "result": {"content": "Alert matched a known-malicious indicator of compromise."}},
  {"action": "notify_analyst", "status": "completed",
   "result": {"notified": true, "message": "Malicious IOC match -- review recommended."}}
]
```

Its third step, `block_ip`, is registered `risk_level: "high"` — the engine
parks it rather than running it, regardless of what the playbook definition
says (see `SECURITY.md`'s separation-of-duties note):

```json
{
  "status": "awaiting_approval",
  "approvals": [{
    "action": "block_ip", "parameters": {"ip": "203.0.113.5"},
    "risk_level": "high", "status": "pending"
  }]
}
```

An admin approves it (`POST /api/playbook-executions/<id>/approve`):

```json
{
  "approvals": [{"status": "approved", "approved_by": "81275de9-...", "approved_at": "2026-09-02T14:04:54Z"}],
  "status": "completed"
}
```

`block_ip` then runs through the `MockResponseProvider` — it records a
structured "would have blocked 203.0.113.5" result and logs it to the audit
trail, but never touches a real firewall or network device (see
`SECURITY.md`; wiring in a real `ResponseProvider` is the only change
needed to make this act for real).

---

Screenshots of these same alerts/incidents in the dashboard UI are in
[`screenshots/`](screenshots/) and linked from the [README](../README.md).
