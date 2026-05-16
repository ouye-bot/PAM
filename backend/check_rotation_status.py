"""检查轮换状态和迁移进度"""
import requests, json, sys

BASE = 'http://127.0.0.1:5000/api'

# Login
r = requests.post(f'{BASE}/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}

print('=== 轮换状态 ===')
r = requests.get(f'{BASE}/keys/rotate-status', headers=headers, timeout=10)
print(json.dumps(r.json(), ensure_ascii=False, indent=2))

print('\n=== 密钥状态 ===')
r = requests.get(f'{BASE}/keys/master-key-status', headers=headers, timeout=10)
print(json.dumps(r.json(), ensure_ascii=False, indent=2))