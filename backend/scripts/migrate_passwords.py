"""
存量密码迁移脚本

功能：将所有用户的明文密码哈希化为 bcrypt 格式
使用场景：部署 P0-1 密码哈希化功能前的数据迁移

使用方法：
    cd backend
    python scripts/migrate_passwords.py

注意事项：
    1. 请先在 .env 中设置 JWT_SECRET（即使仅为迁移也需要）
    2. 执行后原明文密码永久丢失，不可逆
    3. 执行完毕后请立即部署新代码（使用 bcrypt 验证的版本）
    4. 建议在维护窗口期执行，迁移期间登录功能不可用
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)

db_user = os.getenv('DB_USER', 'root')
db_password = os.getenv('DB_PASSWORD')
if not db_password:
    raise RuntimeError("环境变量 DB_PASSWORD 未配置")
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', '3306')
db_name = os.getenv('DB_NAME', 'pam_system')

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='admin')
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)


BCRYPT_PREFIX = '$2b$'


def is_already_hashed(password: str) -> bool:
    return password.startswith(BCRYPT_PREFIX)


def hash_password(password: str) -> str:
    import hashlib
    import bcrypt
    pre = hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')
    return bcrypt.hashpw(pre, bcrypt.gensalt(rounds=12)).decode('utf-8')


def migrate():
    success_count = 0
    skip_count = 0
    fail_count = 0

    with app.app_context():
        users = User.query.all()

        if not users:
            print("[MIGRATE] 数据库中没有用户记录，无需迁移")
            return

        print(f"[MIGRATE] 发现 {len(users)} 个用户，开始迁移...")
        print("-" * 60)

        for user in users:
            try:
                if is_already_hashed(user.password):
                    print(f"  [SKIP]  用户 '{user.username}' (id={user.id}) 密码已是 bcrypt 格式")
                    skip_count += 1
                    continue

                old_prefix = user.password[:10] + '...' if len(user.password) > 10 else user.password
                hashed = hash_password(user.password)
                user.password = hashed
                db.session.flush()
                print(f"  [OK]    用户 '{user.username}' (id={user.id}) 迁移成功")
                print(f"          原密码(前10字符): {old_prefix}")
                success_count += 1

            except Exception as e:
                db.session.rollback()
                print(f"  [FAIL]  用户 '{user.username}' (id={user.id}) 迁移失败: {e}")
                fail_count += 1

        try:
            db.session.commit()
            print("-" * 60)
            print(f"[MIGRATE] 迁移完成！")
            print(f"          成功: {success_count}")
            print(f"          跳过: {skip_count}")
            print(f"          失败: {fail_count}")
        except Exception as e:
            db.session.rollback()
            print(f"[MIGRATE] 提交失败: {e}")
            sys.exit(1)


if __name__ == '__main__':
    print("=" * 60)
    print("  PAM 密码迁移工具 — 明文 → bcrypt 哈希")
    print("=" * 60)
    print()

    confirm = input("此操作不可逆！确认继续？(yes/no): ")
    if confirm.lower() not in ('yes', 'y'):
        print("已取消")
        sys.exit(0)

    migrate()
