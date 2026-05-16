"""国密合规自检服务"""
from datetime import datetime
from app.models import User, Credential, AuditLog, KeyVersion
from app.services.crypto_service import CryptoService


def run_compliance_check() -> dict:
    """执行合规检查，返回结构化报告"""
    checks = []

    # 1. SM2 公钥覆盖率
    total_users = User.query.count()
    with_sm2 = User.query.filter(
        User.sm2_public_key.isnot(None),
        User.sm2_public_key != ''
    ).count()
    pct = round(with_sm2 / total_users * 100, 1) if total_users > 0 else 0
    checks.append({
        'id': 'sm2_coverage', 'name': 'SM2公钥覆盖率',
        'status': 'pass' if pct == 100 else ('warn' if pct >= 80 else 'fail'),
        'detail': f'{with_sm2}/{total_users} 用户已配置SM2公钥',
        'value': f'{pct}%'
    })

    # 2. SM4 加密覆盖率
    total_creds = Credential.query.count()
    encrypted = Credential.query.filter(
        Credential.encrypted_password.isnot(None),
        Credential.encrypted_password != ''
    ).count()
    pct2 = round(encrypted / total_creds * 100, 1) if total_creds > 0 else 0
    checks.append({
        'id': 'sm4_coverage', 'name': 'SM4密码加密覆盖率',
        'status': 'pass' if pct2 == 100 else 'fail',
        'detail': f'{encrypted}/{total_creds} 凭证已SM4加密',
        'value': f'{pct2}%'
    })

    # 3. SM3 哈希链完整性
    logs = AuditLog.query.order_by(AuditLog.id).all()
    previous = ''
    broken_at = None
    for log in logs:
        is_del = 1 if log.is_deleted else 0
        data = f"{log.log_type}|{log.operator}|{log.source_ip}|{log.target_asset}|{log.operation_detail}|{log.result}|{log.timestamp}|{previous}|{is_del}"
        calc = CryptoService.sm3_hash(data)
        if calc != log.current_hash:
            broken_at = log.id
            break
        previous = calc
    checks.append({
        'id': 'sm3_chain', 'name': 'SM3审计哈希链完整性',
        'status': 'pass' if broken_at is None else 'fail',
        'detail': f'{len(logs)}条日志，哈希链完整' if broken_at is None else f'哈希链在ID={broken_at}处断裂',
        'value': '完整' if broken_at is None else f'断裂于#{broken_at}'
    })

    # 4. 算法使用矩阵
    has_sm2 = with_sm2 > 0
    checks.append({
        'id': 'algo_matrix', 'name': '国密算法使用矩阵',
        'status': 'pass' if has_sm2 else 'warn',
        'detail': (
            f'SM2: {"已使用" if has_sm2 else "未使用（无用户配置公钥）"} | '
            'SM3: 审计哈希链、密码历史哈希 | '
            'SM4: 凭证密码加密(CBC)、工作密钥加密、录像文件加密'
        ),
        'value': f'{"3" if has_sm2 else "2"}/3算法覆盖'
    })

    # 5. 密钥管理
    active_key = KeyVersion.query.filter_by(status='active').first()
    rotating_key = KeyVersion.query.filter_by(status='rotating').first()
    total_keys = KeyVersion.query.count()
    checks.append({
        'id': 'key_management', 'name': '密钥生命周期管理',
        'status': 'pass' if active_key else 'fail',
        'detail': (
            f'活跃密钥ID={active_key.id if active_key else "N/A"}, '
            f'密钥版本总数={total_keys}, '
            f'轮换状态={"进行中" if rotating_key else "正常"}, '
            f'支持平滑轮换(rotating→active→retired)'
        ),
        'value': f'v{total_keys}' if active_key else '无活跃密钥'
    })

    pass_count = sum(1 for c in checks if c['status'] == 'pass')
    total = len(checks)
    if pass_count == total:
        grade = 'A'
    elif pass_count >= total - 1:
        grade = 'B'
    elif pass_count >= total - 2:
        grade = 'C'
    else:
        grade = 'D'

    return {
        'checks': checks,
        'pass_count': pass_count,
        'total': total,
        'grade': grade,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }