from flask import Blueprint, request, jsonify

from app import db
from app.models import Rule

rules_bp = Blueprint("rules", __name__)


@rules_bp.route("", methods=["GET"])
def list_rules():
    rules = Rule.query.order_by(Rule.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rules])


@rules_bp.route("", methods=["POST"])
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
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify(rule.to_dict()), 201


@rules_bp.route("/<rule_id>", methods=["PATCH"])
def update_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    data = request.get_json() or {}

    for field in ["name", "rule_type", "condition", "severity", "enabled"]:
        if field in data:
            setattr(rule, field, data[field])

    db.session.commit()
    return jsonify(rule.to_dict())


@rules_bp.route("/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    rule = Rule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    return "", 204
