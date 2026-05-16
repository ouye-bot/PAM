from datetime import datetime
from .. import db

class KeyVersion(db.Model):
    __tablename__ = 'key_versions'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    encrypted_key = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # 关联关系
    credentials = db.relationship('Credential', backref='key_version_ref', lazy=True)