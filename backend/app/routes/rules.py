from flask import Blueprint, request, jsonify, g

from app import db
from app.models import Rule
from app.services.audit import log_action
from app.auth.authorization import require_permission
from app.auth.permissions import RULES_READ, RULES_CREATE, RULES_UPDATE, RULES_DELETE

rules_bp = Blueprint("rules", __name__)

_WRITABLE_FIELDS = ["name", "rule_type", "condition", "severity", "enabled",
                    "mitre_tactic", "mitre_technique", "mitre_subtechnique"]


@rules_bp.route("", methods=["GET"])
@require_permission(RULES_READ)
def list_rules():
    rules = Rule.query.order_by(Rule.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rules])


@rules_bp.route("", methods=["POST"])
@require_permission(RULES_CREATE)
def create_rule():
    data = request.get_json() or {}
    required = ["name", "rule_type", "condition"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    rule = Rule(
        name=data["name"],
        rule_type=data["rule_type"],
        condition=data["condition"],
        severity=data.get("severity", "warning"),
        enabled=data.get("enabled", True),
        mitre_tactic=data.get("mitre_tactic"),
        mitre_technique=data.get("mitre_technique"),
        mitre_subtechnique=data.get("mitre_subtechnique"),
    )
    db.session.add(rule)
    db.session.flush()  # populate rule.id (Python-side UUID default) before logging it
    log_action(g.current_user, "rule.created", "rule", rule.id, {"name": rule.name})
    db.session.commit()
    return jsonify(rule.to_dict()), 201


@rules_bp.route("/<rule_id>", methods=["PATCH"])
@require_permission(RULES_UPDATE)
def update_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    data = request.get_json() or {}

    for field in _WRITABLE_FIELDS:
        if field in data:
            setattr(rule, field, data[field])

    log_action(g.current_user, "rule.updated", "rule", rule.id, {"fields": list(data.keys())})
    db.session.commit()
    return jsonify(rule.to_dict())


@rules_bp.route("/<rule_id>", methods=["DELETE"])
@require_permission(RULES_DELETE)
def delete_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    log_action(g.current_user, "rule.deleted", "rule", rule.id, {"name": rule.name})
    db.session.delete(rule)
    db.session.commit()
    return "", 204
