"""
Validates a playbook definition (name/trigger/steps) before it's ever
stored or executed. This is the security boundary for playbook content:
every step's `action` must already exist in registry.ACTION_REGISTRY (no
dynamic import, no arbitrary code), and every required parameter must be
present. Condition objects are checked for a fixed, small shape -- never
parsed as an expression language (see engine.py's evaluator).
"""
from app.playbooks.models import TRIGGER_TYPES
from app.playbooks.registry import get_action

_CONDITION_OPS = ("==", "!=", ">=", "<=", ">", "<", "in")
MAX_STEPS = 25


def validate_playbook_definition(data: dict) -> list:
    """Returns a list of human-readable error strings; empty means valid."""
    errors = []

    name = data.get("name")
    if not name or not isinstance(name, str) or not name.strip():
        errors.append("name is required.")

    trigger_type = data.get("trigger_type", "manual")
    if trigger_type not in TRIGGER_TYPES:
        errors.append(f"trigger_type must be one of {TRIGGER_TYPES}.")

    trigger_condition = data.get("trigger_condition") or {}
    if not isinstance(trigger_condition, dict):
        errors.append("trigger_condition must be an object.")

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("steps must be a non-empty list.")
        return errors  # nothing further to check without a step list
    if len(steps) > MAX_STEPS:
        errors.append(f"a playbook may have at most {MAX_STEPS} steps.")

    for i, step in enumerate(steps):
        errors.extend(f"step {i}: {e}" for e in validate_step(step))

    return errors


def validate_step(step) -> list:
    errors = []
    if not isinstance(step, dict):
        return ["must be an object."]

    action_name = step.get("action")
    spec = get_action(action_name) if isinstance(action_name, str) else None
    if spec is None:
        errors.append(f"unknown action {action_name!r} -- not in the action registry.")
        return errors  # can't validate parameters against an unknown action

    parameters = step.get("parameters") or {}
    if not isinstance(parameters, dict):
        errors.append("parameters must be an object.")
        parameters = {}

    missing = [p for p in spec.required_parameters if p not in parameters]
    if missing:
        errors.append(f"missing required parameter(s) for {action_name!r}: {', '.join(missing)}")

    condition = step.get("condition")
    if condition is not None:
        errors.extend(validate_condition(condition))

    approval_required = step.get("approval_required")
    if approval_required is not None and not isinstance(approval_required, bool):
        errors.append("approval_required must be a boolean.")

    return errors


def validate_condition(condition) -> list:
    if not isinstance(condition, dict):
        return ["condition must be an object."]
    errors = []
    if "field" not in condition:
        errors.append("condition requires a 'field'.")
    op = condition.get("op", "==")
    if op not in _CONDITION_OPS:
        errors.append(f"condition 'op' must be one of {_CONDITION_OPS}.")
    if "value" not in condition:
        errors.append("condition requires a 'value'.")
    return errors
