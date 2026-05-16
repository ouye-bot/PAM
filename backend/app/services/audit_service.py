import threading
from datetime import datetime
from app import db
from app.models import AuditLog
from app.services.crypto_service import CryptoService
from app.utils.logger import get_logger

logger = get_logger('app.services.audit')

_audit_lock = threading.Lock()

def write_audit_log(log_type, operator, source_ip, target_asset, operation_detail, result='success'):
    """
    写入审计日志，使用哈希链确保防篡改。
    使用全局锁保证并发安全——防止两个线程同时读取"上一条日志"
    的 current_hash 导致哈希链分叉。
    """
    with _audit_lock:
        is_deleted = 0
        timestamp = datetime.now().replace(microsecond=0)

        audit_log = AuditLog(
            log_type=log_type,
            operator=operator,
            source_ip=source_ip,
            target_asset=target_asset,
            operation_detail=operation_detail,
            result=result,
            timestamp=timestamp,
            previous_hash='',
            current_hash='',
            is_deleted=is_deleted
        )
        db.session.add(audit_log)
        db.session.flush()
        db.session.refresh(audit_log)

        last_log = AuditLog.query.order_by(AuditLog.id.desc()).filter(AuditLog.id < audit_log.id).first()
        previous_hash = last_log.current_hash if last_log else ''

        is_deleted_val = 1 if audit_log.is_deleted else 0
        data_to_hash = (
            f"{audit_log.log_type}|{audit_log.operator}|{audit_log.source_ip}|"
            f"{audit_log.target_asset}|{audit_log.operation_detail}|{audit_log.result}|"
            f"{audit_log.timestamp}|{previous_hash}|{is_deleted_val}"
        )
        current_hash = CryptoService.sm3_hash(data_to_hash)

        audit_log.previous_hash = previous_hash
        audit_log.current_hash = current_hash
        db.session.commit()

    return audit_log


def rebuild_hash_chain():
    """Rebuild all audit log hash chains.
    Refuses to rebuild if any locked logs exist — locked hashes are permanently frozen.
    Only safe to rebuild when zero locked logs exist.
    """
    from app.services.crypto_service import CryptoService

    locked_count = AuditLog.query.filter_by(is_locked=True).count()
    if locked_count > 0:
        logger.warning("[HASH-REBUILD] Refusing to rebuild: %d locked logs exist. "
                       "Locked logs have frozen hashes that cannot be rebuilt.", locked_count)
        return -1  # signal: cannot rebuild

    logs = AuditLog.query.order_by(AuditLog.id).all()
    if not logs:
        return 0

    previous_hash = ''
    updated = 0
    for log in logs:
        is_deleted_val = 1 if log.is_deleted else 0
        data_to_hash = (
            f"{log.log_type}|{log.operator}|{log.source_ip}|"
            f"{log.target_asset}|{log.operation_detail}|{log.result}|"
            f"{log.timestamp}|{previous_hash}|{is_deleted_val}"
        )
        log.previous_hash = previous_hash
        log.current_hash = CryptoService.sm3_hash(data_to_hash)
        previous_hash = log.current_hash
        updated += 1

    db.session.commit()
    return updated


def lock_audit_logs(start_id, end_id, operator='system'):
    """Lock audit logs in the given ID range. Does NOT modify hashes."""
    from app.models import AuditLog
    updated = AuditLog.query.filter(
        AuditLog.id >= start_id,
        AuditLog.id <= end_id,
        AuditLog.is_locked == False
    ).update({'is_locked': True}, synchronize_session=False)
    db.session.commit()
    return updated


def unlock_audit_logs(start_id, end_id, operator='system'):
    """Unlock audit logs (admin only)."""
    from app.models import AuditLog
    updated = AuditLog.query.filter(
        AuditLog.id >= start_id,
        AuditLog.id <= end_id,
        AuditLog.is_locked == True
    ).update({'is_locked': False}, synchronize_session=False)
    db.session.commit()
    return updated


def auto_lock_old_logs(retention_days=30):
    """Lock all unlocked logs older than retention_days. Called by scheduler."""
    from datetime import datetime, timedelta
    from app.models import AuditLog
    cutoff = datetime.now() - timedelta(days=retention_days)
    updated = AuditLog.query.filter(
        AuditLog.timestamp <= cutoff,
        AuditLog.is_locked == False
    ).update({'is_locked': True}, synchronize_session=False)
    db.session.commit()
    return updated
