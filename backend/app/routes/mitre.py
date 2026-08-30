from flask import Blueprint, jsonify

from app.models.mitre import MitreTechnique
from app.auth.authorization import require_permission
from app.auth.permissions import MITRE_READ

mitre_bp = Blueprint("mitre", __name__)


@mitre_bp.route("/techniques", methods=["GET"])
@require_permission(MITRE_READ)
def list_techniques():
    techniques = MitreTechnique.query.order_by(MitreTechnique.technique_id).all()
    return jsonify([t.to_dict() for t in techniques])


@mitre_bp.route("/techniques/<technique_id>", methods=["GET"])
@require_permission(MITRE_READ)
def get_technique(technique_id):
    technique = MitreTechnique.query.filter_by(technique_id=technique_id).first_or_404()
    return jsonify(technique.to_dict())
