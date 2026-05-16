"""
Migration 002: Add sm2_recovery_hashes column to users table.
Safe to run multiple times (uses IF NOT EXISTS pattern).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import db
from app import app as flask_app
import sqlalchemy as sa

def upgrade():
    with flask_app.app_context():
        inspector = sa.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('users')]
        if 'sm2_recovery_hashes' not in columns:
            db.session.execute(sa.text(
                'ALTER TABLE users ADD COLUMN sm2_recovery_hashes JSON DEFAULT NULL'
            ))
            db.session.commit()
            print('[MIGRATION 002] Added sm2_recovery_hashes column to users table')
        else:
            print('[MIGRATION 002] sm2_recovery_hashes already exists, skipped')

def downgrade():
    with flask_app.app_context():
        inspector = sa.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('users')]
        if 'sm2_recovery_hashes' in columns:
            db.session.execute(sa.text(
                'ALTER TABLE users DROP COLUMN sm2_recovery_hashes'
            ))
            db.session.commit()
            print('[MIGRATION 002] Dropped sm2_recovery_hashes column')
        else:
            print('[MIGRATION 002] sm2_recovery_hashes not found, skipped')

if __name__ == '__main__':
    upgrade()