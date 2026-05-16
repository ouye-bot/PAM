import requests
import json

BASE = 'http://localhost:5000/api'

# Step 1: Login
r = requests.post(f'{BASE}/auth/login', json={
    'username': 'admin',
    'password': 'admin123'
})
print('1. Login:', r.status_code, r.text)
data = r.json()

if data.get('require_mfa'):
    temp_token = data['temp_token']
    # Step 2: Check if there's a totp_secret by calling setup
    # Try MFA login with a dummy code first
    r2 = requests.post(f'{BASE}/auth/mfa/login', json={
        'temp_token': temp_token,
        'code': '000000'
    })
    print('2. MFA Login:', r2.status_code, r2.text)
    
    if r2.status_code == 401:
        # Invalid code - we need the real TOTP secret
        # Let's try to get it from the app context
        pass

# Step 3: Test detect endpoint
print('\n--- Testing proxy/detect ---')
r3 = requests.post(f'{BASE}/proxy/detect', json={'sql': 'DROP DATABASE test'})
print('detect:', r3.status_code, r3.text)

# Step 4: Test proxy status
print('\n--- Testing proxy/status ---')
r4 = requests.get(f'{BASE}/proxy/status')
print('status:', r4.status_code, r4.text)
