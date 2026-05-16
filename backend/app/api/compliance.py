"""国密合规自检API"""
from flask import Blueprint, jsonify, request
from app.utils.auth import token_required, role_required
from app.services.compliance_checker import run_compliance_check

compliance_bp = Blueprint('compliance', __name__, url_prefix='/api')


@compliance_bp.route('/compliance/report', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_compliance_report():
    """获取国密合规自检报告（支持分页）"""
    report = run_compliance_check()

    # 分页：对 checks 列表分页
    checks = report.get('checks', [])
    page = request.args.get('page', 1, type=int)
    size = request.args.get('size', 10, type=int)
    page = max(1, page)
    size = max(1, min(100, size))

    total = len(checks)
    start = (page - 1) * size
    end = start + size
    paginated_checks = checks[start:end]

    report['checks'] = paginated_checks
    report['total'] = total
    report['page'] = page
    report['size'] = size

    return jsonify({
        'code': 200,
        'data': report
    })
