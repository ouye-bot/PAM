"""国密合规自检API"""
from flask import Blueprint, jsonify
from app.utils.auth import token_required, role_required
from app.services.compliance_checker import run_compliance_check

compliance_bp = Blueprint('compliance', __name__, url_prefix='/api')


@compliance_bp.route('/compliance/report', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_compliance_report():
    """获取国密合规自检报告"""
    report = run_compliance_check()
    return jsonify({
        'code': 200,
        'data': report
    })