"""
The action allowlist. This is the ONLY place a playbook step's `action`
string is resolved to executable code -- app/playbooks/validators.py rejects
any step naming an action not in this dict, and app/playbooks/engine.py
never does anything resembling `getattr(module, name)` or `importlib` on
user-controlled input. If it isn't registered here, it cannot run.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.playbooks import actions

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"


@dataclass(frozen=True)
class ActionSpec:
    name: str
    fn: object
    description: str
    required_parameters: tuple = ()
    risk_level: str = LOW
    requires_approval: bool = False
    supports_dry_run: bool = True
    # True only for the four provider-backed actions (block_ip, disable_user,
    # kill_process, isolate_host) that simulate reaching an external system --
    # see engine.py, which only wraps *these* in a timeout/thread, since the
    # built-in actions touch db.session and must stay on the calling thread.
    external: bool = False


ACTION_REGISTRY = {
    "create_case_note": ActionSpec(
        "create_case_note", actions.create_case_note,
        "Add an investigation note to the incident.",
        required_parameters=("content",), risk_level=LOW,
    ),
    "add_incident_tag": ActionSpec(
        "add_incident_tag", actions.add_incident_tag,
        "Tag the incident.",
        required_parameters=("tag",), risk_level=LOW,
    ),
    "acknowledge_alert": ActionSpec(
        "acknowledge_alert", actions.acknowledge_alert,
        "Mark the triggering alert acknowledged.",
        risk_level=LOW,
    ),
    "resolve_alert": ActionSpec(
        "resolve_alert", actions.resolve_alert,
        "Mark the triggering alert resolved.",
        risk_level=MEDIUM,
    ),
    "notify_analyst": ActionSpec(
        "notify_analyst", actions.notify_analyst,
        "Surface an analyst-facing notification in the SOC dashboard.",
        risk_level=LOW,
    ),
    "create_ioc": ActionSpec(
        "create_ioc", actions.create_ioc,
        "Add a new indicator of compromise to the threat-intel database.",
        required_parameters=("indicator", "indicator_type"), risk_level=MEDIUM,
    ),
    "disable_detection_rule": ActionSpec(
        "disable_detection_rule", actions.disable_detection_rule,
        "Disable a noisy or compromised detection rule.",
        risk_level=MEDIUM, requires_approval=False,
    ),
    "block_ip": ActionSpec(
        "block_ip", actions.block_ip,
        "Block an IP address at the network edge (simulated).",
        required_parameters=("ip",), risk_level=HIGH, requires_approval=True, external=True,
    ),
    "disable_user": ActionSpec(
        "disable_user", actions.disable_user,
        "Disable a user/identity (simulated).",
        required_parameters=("user_id",), risk_level=HIGH, requires_approval=True, external=True,
    ),
    "kill_process": ActionSpec(
        "kill_process", actions.kill_process,
        "Terminate a process on an endpoint (simulated).",
        required_parameters=("host", "process"), risk_level=CRITICAL, requires_approval=True, external=True,
    ),
    "isolate_host": ActionSpec(
        "isolate_host", actions.isolate_host,
        "Isolate a host from the network (simulated).",
        required_parameters=("host",), risk_level=CRITICAL, requires_approval=True, external=True,
    ),
}


def get_action(name: str) -> ActionSpec | None:
    return ACTION_REGISTRY.get(name)


def list_actions() -> list:
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "required_parameters": list(spec.required_parameters),
            "risk_level": spec.risk_level,
            "requires_approval": spec.requires_approval,
            "supports_dry_run": spec.supports_dry_run,
        }
        for spec in ACTION_REGISTRY.values()
    ]
