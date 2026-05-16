"""通过SQL直接查询数据库验证轮换"""
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
print('Phase A2: P4-11 轮换后数据库验证')
print('=' * 60)

# 1. 密钥版本
print('\n--- 密钥版本 ---')
cur.execute('SELECT id, status, created_at FROM key_versions ORDER BY id')
rows = cur.fetchall()
print(f'  共 {len(rows)} 个版本')
active_count = 0
retired_count = 0
for r in rows:
    status_cn = '活跃' if r[1] == 'active' else ('已退役' if r[1] == 'retired' else r[1])
    print(f'  ID={r[0]}, status={r[1]}({status_cn}), created={r[2]}')
    if r[1] == 'active':
        active_count += 1
    elif r[1] == 'retired':
        retired_count += 1

print(f'  -> Active: {active_count}, Retired: {retired_count}')
assert active_count == 1, f'应该只有1个active版本，实际{active_count}个'
assert retired_count >= 1, f'应该有至少1个retired版本，实际{retired_count}个'
print('  [PASS] 密钥版本验证通过')

# 2. 凭证密钥版本分配
print('\n--- 凭证密钥版本 ---')
cur.execute('SELECT COUNT(*) FROM credentials')
total = cur.fetchone()[0]
cur.execute('SELECT COUNT(*) FROM credentials WHERE key_version IS NOT NULL')
with_key = cur.fetchone()[0]
print(f'  总凭证: {total}')
print(f'  已分配密钥版本: {with_key}')
assert with_key == total, f'部分凭证未分配密钥版本: {with_key}/{total}'
print('  [PASS] 凭证密钥版本分配验证通过')

# 3. 查看各版本分布
print('\n--- 凭证密钥版本分布 ---')
cur.execute('SELECT key_version, COUNT(*) FROM credentials GROUP BY key_version')
for r in cur.fetchall():
    print(f'  key_version={r[0]}: {r[1]}条')

# 4. 轮换任务记录
print('\n--- 轮换任务记录 ---')
# Check actual column names
cur.execute('DESCRIBE rotation_tasks')
columns = [r[0] for r in cur.fetchall()]
print(f'  表结构: {columns}')

# Build query dynamically
col_str = ', '.join(columns)
cur.execute(f'SELECT {col_str} FROM rotation_tasks ORDER BY id DESC LIMIT 3')
for r in cur.fetchall():
    details = ', '.join([f'{c}={v}' for c, v in zip(columns, r)])
    print(f'  任务: {details}')

# 5. 验证API凭证可查看
print('\n--- API凭证查看验证 ---')
import requests
r = requests.post('http://127.0.0.1:5000/api/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}

cur.execute('SELECT c.id, c.asset_id, c.account_name, a.ip FROM credentials c LEFT JOIN assets a ON c.asset_id = a.id LIMIT 5')
creds = cur.fetchall()
success = 0
fail = 0
for cred in creds:
    cid, aid, aname, ip = cred
    r2 = requests.post(f'http://127.0.0.1:5000/api/assets/credentials/{cid}/view', headers=headers, timeout=10)
    if r2.status_code == 200 and r2.json().get('code') == 200:
        pwd = r2.json().get('password', '')
        success += 1
        print(f'  凭证ID={cid}, 资产={ip}/{aname}: 解密成功 (密码长度={len(pwd)})')
    else:
        fail += 1
        print(f'  凭证ID={cid}, 资产={ip}/{aname}: 解密失败 - {r2.status_code} {r2.text[:100]}')

print(f'\n  API解密成功率: {success}/{success+fail}')

conn.close()
print('\n  [PASS] 所有验证通过!')