import requests, json, socket, hashlib, time, pymysql

s = requests.Session()
login_resp = s.post('http://127.0.0.1:5000/api/auth/login', json={'username': 'admin', 'password': 'admin123'})
token = login_resp.json().get('token', '')
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

# ====== Test 1: Password rotation for MySQL ======
print('=' * 60)
print('Test 1: MySQL Password Rotation')
print('=' * 60)

assets_resp = s.get('http://127.0.0.1:5000/api/assets', headers=headers)
assets = assets_resp.json() if isinstance(assets_resp.json(), list) else []
mysql_assets = [a for a in assets if a.get('os_type', '').lower() == 'mysql']
print(f'MySQL assets: {len(mysql_assets)}')

if not mysql_assets:
    # Create one if not exists
    create_resp = s.post('http://127.0.0.1:5000/api/assets', json={
        'host': '127.0.0.1', 'port': 3306, 'username': 'root',
        'name': 'test_mysql', 'password': '123456', 'asset_type': 'mysql'
    }, headers=headers)
    print(f'Create asset: {create_resp.status_code}')
    assets_resp = s.get('http://127.0.0.1:5000/api/assets', headers=headers)
    assets = assets_resp.json() if isinstance(assets_resp.json(), list) else []
    mysql_assets = [a for a in assets if a.get('os_type', '').lower() == 'mysql']

asset = mysql_assets[0]
asset_id = asset['id']
print(f'Testing rotation on asset ID={asset_id}, ip={asset.get("ip")}:{asset.get("ssh_port")}')

rotate_resp = s.post(f'http://127.0.0.1:5000/api/rotation/trigger/{asset_id}', headers=headers)
print(f'Rotation response: {rotate_resp.status_code}')
print(f'  Body: {json.dumps(rotate_resp.json(), ensure_ascii=False)}')

if rotate_resp.status_code == 200 and rotate_resp.json().get('code') == 200:
    print('PASS: MySQL rotation succeeded')
else:
    print('FAIL: MySQL rotation failed')

# ====== Test 2: Proxy Token auth ======
print()
print('=' * 60)
print('Test 2: Proxy Token Authentication')
print('=' * 60)

# Get token
token_resp = s.post('http://127.0.0.1:5000/api/proxy/token', json={'asset_id': asset_id}, headers=headers)
token_data = token_resp.json()
print(f'Token response: {token_resp.status_code}')
proxy_token = token_data.get('token', '')
print(f'Token: {proxy_token[:16]}...')

if not proxy_token:
    print('FAIL: No token returned')
else:
    # Simulate MySQL native password auth
    scramble = b'\x00' * 8 + b'\x01' * 12  # We'll get the real scramble from the handshake
    
    # Connect to proxy to get real handshake
    sock = socket.socket()
    sock.settimeout(5)
    sock.connect(('127.0.0.1', 3307))
    
    # Read handshake
    handshake = sock.recv(4096)
    print(f'Handshake received: {len(handshake)} bytes')
    
    # Parse scramble from handshake (MySQL protocol)
    offset = 0
    protocol_version = handshake[offset]
    offset += 1
    # Server version (null-terminated)
    null_pos = handshake.find(b'\x00', offset)
    server_version = handshake[offset:null_pos]
    offset = null_pos + 1
    
    # Connection ID (4 bytes)
    conn_id = int.from_bytes(handshake[offset:offset+4], 'little')
    offset += 4
    
    # Auth plugin data part 1 (8 bytes)
    auth_plugin_data_part1 = handshake[offset:offset+8]
    offset += 8
    
    # Filler (1 byte)
    offset += 1
    
    # Capability flags (2 bytes)
    cap_low = int.from_bytes(handshake[offset:offset+2], 'little')
    offset += 2
    
    # Character set (1 byte)
    offset += 1
    
    # Status flags (2 bytes)
    offset += 2
    
    # Capability flags upper (2 bytes)
    cap_high = int.from_bytes(handshake[offset:offset+2], 'little')
    offset += 2
    
    # Auth plugin data len (1 byte)
    auth_plugin_data_len = handshake[offset]
    offset += 1
    
    # Reserved (10 bytes)
    offset += 10
    
    # Auth plugin data part 2 (at least 12 bytes)
    if auth_plugin_data_len > 0:
        auth_plugin_data_part2 = handshake[offset:offset+max(12, auth_plugin_data_len - 8)]
    else:
        auth_plugin_data_part2 = handshake[offset:offset+12]
    
    real_scramble = auth_plugin_data_part1 + auth_plugin_data_part2[:12]
    print(f'Real scramble: {real_scramble.hex()}')
    print(f'Server version: {server_version.decode(errors="replace")}')
    
    # Now manually test validate_token_by_auth logic
    from app.services.mysql_proxy import validate_token_by_auth
    
    # First, add the token to the cache
    from app.services.mysql_proxy import add_token
    add_token(asset_id, '127.0.0.1', 'root', proxy_token)
    print(f'Token added to cache: {proxy_token[:16]}...')
    
    # Now test validation
    token_bytes = proxy_token.encode()
    stage1 = hashlib.sha1(token_bytes).digest()
    stage2 = hashlib.sha1(stage1).digest()
    
    def xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))
    
    expected_auth = xor_bytes(stage1, hashlib.sha1(real_scramble + stage2).digest())
    print(f'Computed expected auth: {expected_auth.hex()[:20]}...')
    
    # Test validate_token_by_auth directly
    result = validate_token_by_auth(real_scramble, expected_auth)
    if result:
        print(f'PASS: validate_token_by_auth returned valid token_info')
        print(f'  asset_id={result.get("asset_id")}, username={result.get("username")}')
    else:
        print('FAIL: validate_token_by_auth returned None')
    
    sock.close()

# ====== Test 3: Full proxy connection with token ======
print()
print('=' * 60)
print('Test 3: Full Proxy Connection via mysql client')
print('=' * 60)

# We can use pymysql with proxy
try:
    proxy_conn = pymysql.connect(
        host='127.0.0.1', port=3307,
        user='root', password=proxy_token,
        connect_timeout=5, read_timeout=5
    )
    print('PASS: Connected through proxy on 3307')
    proxy_conn.close()
except Exception as e:
    print(f'FAIL: Proxy connection failed: {e}')