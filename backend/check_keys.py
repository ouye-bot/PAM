import requests
r = requests.post('http://127.0.0.1:5000/api/auth/login', json={'username':'admin','password':'admin123'}, timeout=10)
token = r.json().get('token')
headers = {'Authorization': f'Bearer {token}'}

# Check current rotation status
r = requests.get('http://127.0.0.1:5000/api/keys/rotate-status', headers=headers, timeout=10)
print('rotate-status:', r.text[:500])

# Check master key status
r = requests.get('http://127.0.0.1:5000/api/keys/master-key-status', headers=headers, timeout=10)
print('master-key-status:', r.text[:500])