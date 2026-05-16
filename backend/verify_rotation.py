"""验证轮换后密钥版本和凭证可解密性"""
import requests, json, sys, pymysql

BASE = 'http://127.0.0.1:5000/api'
passed = 0
failed = 0

def test(name, condition, detail=''):
    global passed, failed
    if condition:
        passed += 1
        print(f'  [PASS] {name}')
    else:
        failed += 1
        print(f'  [FAIL] {name} - {detail}')

# Login
r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}
test('登录成功', bool(token))

# === 验证1: 数据库密钥版本 ===
print('\n--- 验证1: 数据库密钥版本 ---')
try:
    conn = pymysql.connect(host='127.0.0.1', port=3307, user='pam_user', passwd='Pam123456!', db='pam_db')
    cur = conn.cursor()
    cur.execute('SELECT id, status, created_at FROM key_versions ORDER BY id')
    rows = cur.fetchall()
    test('存在密钥版本记录', len(rows) > 0, f'共{len(rows)}个版本')
    for row in rows:
        status_ok = '正常' if row[1] == 'active' else ('已退役' if row[1] == 'retired' else row[1])
        print(f'  版本ID={row[0]}, 状态={row[1]}({status_ok}), 创建时间={row[2]}')
    # 验证有且仅有一个active版本
    active = [r for r in rows if r[1] == 'active']
    retired = [r for r in rows if r[1] == 'retired']
    test('存在active版本', len(active) == 1, f'active版本数: {len(active)}')
    test('旧版本已retired', len(retired) >= 1, f'retired版本数: {len(retired)}')
    # 最新的active应该是版本6
    cur.execute('SELECT MAX(id) FROM key_versions WHERE status="active"')
    max_active = cur.fetchone()[0]
    test(f'当前active密钥ID={max_active}', max_active is not None)
    print(f'  当前active密钥版本: {max_active}')
    
    # 验证凭证使用的密钥版本
    cur.execute('SELECT COUNT(*) FROM credentials WHERE key_version_id IS NOT NULL')
    total_with_key = cur.fetchone()[0]
    cur.execute('SELECT COUNT(*) FROM credentials')
    total_creds = cur.fetchone()[0]
    test(f'凭证已分配密钥版本', total_with_key == total_creds, f'{total_with_key}/{total_creds}')
    
    conn.close()
except Exception as e:
    test('数据库查询失败', False, str(e))

# === 验证2: 凭证可解密 ===
print('\n--- 验证2: 凭证可解密 ---')
try:
    r = requests.get(f'{BASE}/assets', headers=headers, timeout=10)
    assets = r.json()
    if isinstance(assets, list):
        asset_list = assets
    else:
        asset_list = assets.get('data', assets.get('assets', []))
    test('资产列表可获取', len(asset_list) > 0, f'共{len(asset_list)}个资产')
    
    # 查看第一个资产的凭证
    for asset in asset_list[:2]:
        aid = asset.get('id', asset.get('asset_id'))
        if aid:
            r2 = requests.get(f'{BASE}/assets/{aid}/credential', headers=headers, timeout=10)
            if r2.status_code == 200:
                cred = r2.json()
                if isinstance(cred, dict) and cred.get('code') == 200:
                    cred_data = cred.get('data', {})
                elif isinstance(cred, dict):
                    cred_data = cred
                else:
                    cred_data = {}
                has_pwd = bool(cred_data.get('password') or cred_data.get('login_password'))
                test(f'资产{aid}凭证可解密', has_pwd, f'状态码={r2.status_code}')
            else:
                test(f'资产{aid}凭证请求', r2.status_code == 200, f'状态码={r2.status_code}')
except Exception as e:
    test('凭证解密验证失败', False, str(e))

# === 汇总 ===
print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)