from datetime import datetime
from .. import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    log_type = db.Column(db.String(50), nullable=False)
    operator = db.Column(db.String(100), nullable=False)
    source_ip = db.Column(db.String(50), nullable=False)
    target_asset = db.Column(db.String(100), nullable=False)
    operation_detail = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    previous_hash = db.Column(db.String(64), nullable=True)
    current_hash = db.Column(db.String(64), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)