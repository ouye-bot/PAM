from datetime import datetime
from .. import db

class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(50), nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    os_type = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(20), default='local', nullable=False)
    ssh_port = db.Column(db.Integer, default=22)
    status = db.Column(db.String(20), default='active')
    connectivity = db.Column(db.String(20), default='unknown')
    last_check_time = db.Column(db.DateTime, nullable=True)
    last_agent_login_time = db.Column(db.DateTime, nullable=True)
    allowed_roles = db.Column(db.String(255), default='admin')
    host_fingerprint = db.Column(db.String(255), nullable=True)
    fingerprint_type = db.Column(db.String(20), nullable=True)
    fingerprint_collected_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    __table_args__ = (
        db.UniqueConstraint('ip', 'ssh_port', name='_ip_port_uc'),
    )

    credentials = db.relationship('Credential', backref='asset', lazy=True)

    def get_display_os_type(self):
        """获取显示用的操作系统类型"""
        os_type_mapping = {
            'ssh': 'Linux',
            'linux': 'Linux',
            'ubuntu': 'Ubuntu',
            'debian': 'Debian',
            'centos': 'CentOS',
            'rhel': 'RHEL',
            'windows': 'Windows',
            'mysql': 'MySQL'
        }
        return os_type_mapping.get(self.os_type.lower(), self.os_type)

    def to_dict(self):
        return {
            'id': self.id,
            'ip': self.ip,
            'hostname': self.hostname,
            'os_type': self.os_type if self.os_type else 'linux',
            'account_type': self.account_type or 'local',
            'ssh_port': self.ssh_port,
            'status': self.status,
            'connectivity': self.connectivity,
            'last_check_time': self.last_check_time.isoformat() if self.last_check_time else None,
            'last_agent_login_time': self.last_agent_login_time.isoformat() if self.last_agent_login_time else None,
            'allowed_roles': self.allowed_roles,
            'host_fingerprint': self.host_fingerprint,
            'fingerprint_type': self.fingerprint_type,
            'fingerprint_collected_at': self.fingerprint_collected_at.isoformat() if self.fingerprint_collected_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
