import requests
r = requests.post('http://127.0.0.1:5000/api/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}
r = requests.get('http://127.0.0.1:5000/api/audit/logs?page=1&page_size=50', headers=headers, timeout=10)
data = r.json()
for item in data['data']['items']:
    if item['id'] in (387, 388, 389):
        print(f"ID={item['id']} type={item['log_type']} detail={item['operation_detail'][:120]}")