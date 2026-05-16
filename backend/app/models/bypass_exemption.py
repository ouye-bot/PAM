from datetime import datetime
from .. import db

class BypassExemption(db.Model):
    __tablename__ = 'bypass_exemptions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    asset_id = db.Column(db.Integer, nullable=False)
    source_ip = db.Column(db.String(50), nullable=False, default='')
    exempted_by = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.String(500), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'source_ip', name='uq_asset_source'),
    )
