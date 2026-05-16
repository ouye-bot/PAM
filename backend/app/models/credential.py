from datetime import datetime
from .. import db
from ..services.crypto_service import CryptoService
from app.utils.logger import get_logger

logger = get_logger('app.models.credential')

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    key_version = db.Column(db.Integer, db.ForeignKey('key_versions.id'), nullable=False)
    previous_passwords = db.Column(db.Text, default='[]')
    pending_password = db.Column(db.String(255), nullable=True)
    pending_key_version = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    def get_password(self):
        """
        获取解密后的密码
        """
        try:
            return CryptoService.sm4_decrypt(self.encrypted_password, self.key_version)
        except Exception as e:
            logger.error(f"[Credential] Failed to decrypt password: {str(e)}", exc_info=True)
            return None