"""P4-16 国密合规自检报告验证"""
import requests, json, sys

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

r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}
test('登录成功', bool(token))

print('=' * 60)
print('P4-16 国密合规自检报告验证')
print('=' * 60)

# 1. 端点可用
print('\n--- 1. 端点可用 ---')
try:
    r = requests.get(f'{BASE}/compliance/report', headers=headers, timeout=10)
    test('返回200', r.status_code == 200, str(r.status_code))
except:
    test('端点不可用', False)

# 2. 报告结构完整性
print('\n--- 2. 报告结构 ---')
r = requests.get(f'{BASE}/compliance/report', headers=headers, timeout=10)
data = r.json().get('data', {})
test('存在checks数组', isinstance(data.get('checks'), list), str(type(data.get('checks'))))
test('存在pass_count', 'pass_count' in data, str(data.keys()))
test('存在total', 'total' in data, str(data.keys()))
test('存在grade', 'grade' in data, str(data.get('grade')))
test('存在generated_at', 'generated_at' in data, str(data.get('generated_at')))
test('5项检查', data.get('total') == 5, f"total={data.get('total')}")

# 3. 每项检查结构
print('\n--- 3. 检查项结构 ---')
for check in data.get('checks', []):
    cid = check.get('id')
    test(f'{cid}: 有id', bool(check.get('id')), str(check.get('id')))
    test(f'{cid}: 有name', bool(check.get('name')), str(check.get('name')))
    test(f'{cid}: 有status', check.get('status') in ('pass', 'warn', 'fail'), str(check.get('status')))
    test(f'{cid}: 有detail', bool(check.get('detail')), str(check.get('detail')))
    test(f'{cid}: 有value', bool(check.get('value')), str(check.get('value')))

# 4. 前端编译产物
print('\n--- 4. 前端编译 ---')
import os
dist_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist', 'assets')
compliance_files = [f for f in os.listdir(dist_dir) if 'ComplianceReport' in f]
test('ComplianceReport编译产物存在', len(compliance_files) == 2, str(compliance_files))

print('\n' + '=' * 60)
print(f'验证完成: {passed} PASS / {failed} FAIL / {passed+failed} 总计')
print('=' * 60)
sys.exit(0 if failed == 0 else 1)