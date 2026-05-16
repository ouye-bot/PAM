"""P4-18 主机指纹校验 - DB迁移与验证"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

import pymysql

conn = pymysql.connect(
    host=os.getenv('DB_HOST', '127.0.0.1'),
    port=int(os.getenv('DB_PORT', '3307')),
    user=os.getenv('DB_USER', 'pam_user'),
    password=os.getenv('DB_PASSWORD', 'Pam123456!'),
    db=os.getenv('DB_NAME', 'pam_db')
)
cur = conn.cursor()

print('=' * 60)
print('P4-18 DB迁移')
print('=' * 60)

# Check if columns exist
cur.execute("SHOW COLUMNS FROM assets LIKE 'host_fingerprint'")
if cur.fetchone():
    print('host_fingerprint 已存在，跳过')
else:
    cur.execute("ALTER TABLE assets ADD COLUMN host_fingerprint VARCHAR(255)")
    print('host_fingerprint 已添加')

cur.execute("SHOW COLUMNS FROM assets LIKE 'fingerprint_type'")
if cur.fetchone():
    print('fingerprint_type 已存在，跳过')
else:
    cur.execute("ALTER TABLE assets ADD COLUMN fingerprint_type VARCHAR(20)")
    print('fingerprint_type 已添加')

cur.execute("SHOW COLUMNS FROM assets LIKE 'fingerprint_collected_at'")
if cur.fetchone():
    print('fingerprint_collected_at 已存在，跳过')
else:
    cur.execute("ALTER TABLE assets ADD COLUMN fingerprint_collected_at DATETIME")
    print('fingerprint_collected_at 已添加')

conn.commit()
print('\nDB迁移完成!')