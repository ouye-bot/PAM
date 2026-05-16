from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from app import db
from app.utils.logger import get_logger

logger = get_logger('app.services.bypass_exemption')

_exemptions = {}

def _load_cache():
    from app.models.bypass_exemption import BypassExemption
    _exemptions.clear()
    try:
        now = datetime.now()
        records = BypassExemption.query.filter(
            db.or_(BypassExemption.expires_at.is_(None), BypassExemption.expires_at > now)
        ).all()
        for r in records:
            key = f"{r.asset_id}:{r.source_ip}"
            _exemptions[key] = r.expires_at
        logger.info("Loaded %d active exemption(s) into cache", len(_exemptions))
    except Exception as e:
        logger.warning("Exemption cache load deferred (table may not exist yet): %s", e)

def init_cache():
    _load_cache()

def is_exempted(asset_id, source_ip=''):
    if source_ip:
        key = f"{asset_id}:{source_ip}"
        if key in _exemptions:
            expires_at = _exemptions[key]
            if expires_at is None:
                return True
            if datetime.now() < expires_at:
                return True
            del _exemptions[key]
            return False
        from app.models.bypass_exemption import BypassExemption
        record = BypassExemption.query.filter_by(asset_id=asset_id, source_ip=source_ip).first()
        if record is not None and (record.expires_at is None or datetime.now() < record.expires_at):
            _exemptions[key] = record.expires_at
            return True
        return False
    prefix = f"{asset_id}:"
    for key, expires_at in list(_exemptions.items()):
        if key.startswith(prefix):
            if expires_at is not None and datetime.now() >= expires_at:
                del _exemptions[key]
                continue
            return True
    from app.models.bypass_exemption import BypassExemption
    records = BypassExemption.query.filter_by(asset_id=asset_id).all()
    now = datetime.now()
    for record in records:
        if record.expires_at is None or now < record.expires_at:
            key = f"{record.asset_id}:{record.source_ip}"
            _exemptions[key] = record.expires_at
            return True
    return False

def add_exemption(asset_id, source_ip, exempted_by, reason):
    from app.models.bypass_exemption import BypassExemption
    expires_at = datetime.now() + timedelta(seconds=300)
    try:
        record = BypassExemption(
            asset_id=asset_id,
            source_ip=source_ip,
            exempted_by=exempted_by,
            reason=reason,
            expires_at=expires_at
        )
        db.session.add(record)
        db.session.commit()
        key = f"{asset_id}:{source_ip}"
        _exemptions[key] = expires_at
        logger.info("Exemption added: asset_id=%d, source_ip='%s', expires_at=%s", asset_id, source_ip, expires_at)
        return True
    except IntegrityError:
        db.session.rollback()
        existing = BypassExemption.query.filter_by(asset_id=asset_id, source_ip=source_ip).first()
        if existing:
            existing.exempted_by = exempted_by
            existing.reason = reason
            existing.expires_at = expires_at
            db.session.commit()
            key = f"{asset_id}:{source_ip}"
            _exemptions[key] = expires_at
            logger.info("Exemption updated: asset_id=%d, source_ip='%s'", asset_id, source_ip)
            return True
        logger.error("Failed to add exemption for asset_id=%d, source_ip='%s'", asset_id, source_ip)
        return False
    except Exception as e:
        db.session.rollback()
        logger.error("Error adding exemption: %s", e)
        return False

def remove_exemption(asset_id, source_ip):
    from app.models.bypass_exemption import BypassExemption
    try:
        record = BypassExemption.query.filter_by(asset_id=asset_id, source_ip=source_ip).first()
        if record:
            db.session.delete(record)
            db.session.commit()
        key = f"{asset_id}:{source_ip}"
        _exemptions.pop(key, None)
        logger.info("Exemption removed: asset_id=%d, source_ip='%s'", asset_id, source_ip)
        return True
    except Exception as e:
        db.session.rollback()
        logger.error("Error removing exemption: %s", e)
        return False

def clear_exemptions_for_asset(asset_id):
    from app.models.bypass_exemption import BypassExemption
    try:
        BypassExemption.query.filter_by(asset_id=asset_id).delete()
        db.session.commit()
        keys_to_remove = [k for k in _exemptions if k.startswith(f"{asset_id}:")]
        for k in keys_to_remove:
            del _exemptions[k]
        logger.info("All exemptions cleared for asset_id=%d", asset_id)
        return True
    except Exception as e:
        db.session.rollback()
        logger.error("Error clearing exemptions for asset %d: %s", asset_id, e)
        return False
