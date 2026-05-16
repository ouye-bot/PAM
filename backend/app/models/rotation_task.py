from datetime import datetime
from app import db

class RotationTask(db.Model):
    __tablename__ = 'rotation_tasks'

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credentials.id'), nullable=False)
    executed_at = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(20), nullable=False)
    error_msg = db.Column(db.Text, nullable=True)
    old_password_hash = db.Column(db.String(128), nullable=True)
    new_password_hash = db.Column(db.String(128), nullable=True)

    # 关联关系
    credential = db.relationship('Credential', backref=db.backref('rotation_tasks', lazy=True))
