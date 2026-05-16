from datetime import datetime
from app import db

class SessionRecord(db.Model):
    __tablename__ = 'session_records'
    
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    user_id = db.Column(db.Integer, default=1)
    operator_name = db.Column(db.String(100), nullable=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.now)
    end_time = db.Column(db.DateTime, nullable=True)
    recording_path = db.Column(db.String(500), nullable=False)
    
    asset = db.relationship('Asset', backref=db.backref('session_records', lazy=True))