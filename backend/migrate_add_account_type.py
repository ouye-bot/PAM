import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

db_user = os.getenv('DB_USER', 'root')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', '3306')
db_name = os.getenv('DB_NAME', 'pam_system')

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from app import db
db.init_app(app)

with app.app_context():
    import sqlalchemy as sa
    inspector = sa.inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('assets')]

    if 'account_type' not in columns:
        print("[MIGRATE] Adding account_type column to assets table...")
        db.session.execute(sa.text(
            "ALTER TABLE assets ADD COLUMN account_type VARCHAR(20) NOT NULL DEFAULT 'local'"
        ))
        db.session.commit()
        print("[MIGRATE] account_type column added successfully, default = 'local'")
    else:
        print("[MIGRATE] account_type column already exists, skipping")

    from app.models import Asset
    updated = Asset.query.filter(Asset.account_type.is_(None)).update(
        {'account_type': 'local'}, synchronize_session='fetch'
    )
    db.session.commit()
    if updated:
        print(f"[MIGRATE] Updated {updated} assets with account_type = 'local'")
    else:
        print("[MIGRATE] No assets needed account_type update")

    total = Asset.query.count()
    domain_count = Asset.query.filter(Asset.account_type == 'domain').count()
    local_count = Asset.query.filter(Asset.account_type == 'local').count()
    print(f"[MIGRATE] Verification: total={total}, local={local_count}, domain={domain_count}")
    print("[MIGRATE] Migration completed")
