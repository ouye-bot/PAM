import requests, json, socket, hashlib, struct, time

s = requests.Session()
login_resp = s.post('http://127.0.0.1:5000/api/auth/login', json={'username': 'admin', 'password': 'admin123'})
token = login_resp.json().get('token', '')
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

assets_resp = s.get('http://127.0.0.1:5000/api/assets', headers=headers)
assets = assets_resp.json() if isinstance(assets_resp.json(), list) else []
mysql_assets = [a for a in assets if a.get('os_type', '').lower() == 'mysql']
asset_id = mysql_assets[0]['id']

token_resp = s.post('http://127.0.0.1:5000/api/proxy/token', json={'asset_id': asset_id}, headers=headers)
proxy_token = token_resp.json().get('token', '')
print(f'Token (first 40 chars): {proxy_token[:40]}')
print(f'Token length: {len(proxy_token)}')

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def compute_auth_resp(password, scramble):
    pwd_bytes = password.encode()
    stage1 = hashlib.sha1(pwd_bytes).digest()
    stage2 = hashlib.sha1(stage1).digest()
    result = xor_bytes(stage1, hashlib.sha1(scramble + stage2).digest())
    return result

# Connect and get handshake
sock = socket.socket()
sock.settimeout(5)
sock.connect(('127.0.0.1', 3307))

header = sock.recv(4)
hdr_len = header[0] | (header[1] << 8) | (header[2] << 16)
handshake = b''
while len(handshake) < hdr_len:
    chunk = sock.recv(hdr_len - len(handshake))
    handshake += chunk

off = 0
off += 1  # proto ver
null_pos = handshake.find(b'\x00', off)
server_ver = handshake[off:null_pos]; off = null_pos + 1
off += 4  # conn_id
auth_part1 = handshake[off:off+8]; off += 8
off += 1  # filler
off += 2 + 1 + 2 + 2  # cap_low + charset + status + cap_high
auth_data_len = handshake[off]; off += 1
off += 10  # reserved
auth_part2 = handshake[off:off+12]  # exactly 12 bytes

scramble = auth_part1 + auth_part2
print(f'\nScramble from handshake: {scramble.hex()} ({len(scramble)} bytes)')

# Compute expected auth response
expected_auth = compute_auth_resp(proxy_token, scramble)
print(f'Expected auth response: {expected_auth.hex()} ({len(expected_auth)} bytes)')
print(f'SHA1(token) = {hashlib.sha1(proxy_token.encode()).digest().hex()}')

# Manually check if this token would be accepted
# Connect to the proxy's validation logic:
token_bytes = proxy_token.encode()
stage1 = hashlib.sha1(token_bytes).digest()
stage2 = hashlib.sha1(stage1).digest()
computed = xor_bytes(stage1, hashlib.sha1(scramble + stage2).digest())
print(f'Manually computed: {computed.hex()}')
print(f'Match: {computed == expected_auth}')

# Now send through proxy
client_cap = 0x00a685 | 0x000800 | 0x080000  # includes CLIENT_PLUGIN_AUTH
max_pkt_size = 16777215
charset_val = 33

auth_body = struct.pack('<II', client_cap, max_pkt_size)
auth_body += struct.pack('<B', charset_val)
auth_body += b'\x00' * 23
auth_body += b'root\x00'
auth_body += bytes([len(expected_auth)]) + expected_auth
auth_body += b'mysql\x00'
auth_body += b'mysql_native_password\x00'

pkt_len = len(auth_body)
pkt_header = struct.pack('<I', pkt_len)[:3] + bytes([1])
sock.sendall(pkt_header + auth_body)
print(f'\nSent auth packet: body_len={pkt_len}')

# Read response
resp_header = sock.recv(4)
if resp_header:
    resp_len = resp_header[0] | (resp_header[1] << 8) | (resp_header[2] << 16)
    resp_seq = resp_header[3]
    resp_body = b''
    while len(resp_body) < resp_len:
        chunk = sock.recv(resp_len - len(resp_body))
        resp_body += chunk
    
    if resp_body[0] == 0x00:
        print('PASS: Authentication succeeded!')
    elif resp_body[0] == 0xFF:
        err_code = struct.unpack('<H', resp_body[1:3])[0]
        err_msg = resp_body[3:].decode(errors='replace')
        print(f'FAIL: Error {err_code}: {err_msg}')
elif auth_data_len > 0:
    # Might be caching_sha2_password exchange - read more
    pass

sock.close()

# Now try the same through a SECOND connection, also check if token is in cache
print(f'\n--- Second connection test ---')
sock2 = socket.socket()
sock2.settimeout(5)
sock2.connect(('127.0.0.1', 3307))

header2 = sock2.recv(4)
hdr_len2 = header2[0] | (header2[1] << 8) | (header2[2] << 16)
handshake2 = b''
while len(handshake2) < hdr_len2:
    chunk = sock2.recv(hdr_len2 - len(handshake2))
    handshake2 += chunk

off2 = 0
off2 += 1
null_pos2 = handshake2.find(b'\x00', off2)
off2 = null_pos2 + 1
off2 += 4
auth_part1_2 = handshake2[off2:off2+8]; off2 += 8
off2 += 1 + 2 + 1 + 2 + 2 + 1 + 10
auth_part2_2 = handshake2[off2:off2+12]
scramble2 = auth_part1_2 + auth_part2_2

expected_auth2 = compute_auth_resp(proxy_token, scramble2)
print(f'Scramble2: {scramble2.hex()}')
print(f'Auth2: {expected_auth2.hex()}')

auth_body2 = struct.pack('<II', client_cap, max_pkt_size)
auth_body2 += struct.pack('<B', charset_val)
auth_body2 += b'\x00' * 23
auth_body2 += b'root\x00'
auth_body2 += bytes([len(expected_auth2)]) + expected_auth2

pkt_len2 = len(auth_body2)
pkt_header2 = struct.pack('<I', pkt_len2)[:3] + bytes([1])
sock2.sendall(pkt_header2 + auth_body2)

resp_header2 = sock2.recv(4)
if resp_header2:
    resp_len2 = resp_header2[0] | (resp_header2[1] << 8) | (resp_header2[2] << 16)
    resp_body2 = b''
    while len(resp_body2) < resp_len2:
        chunk = sock2.recv(resp_len2 - len(resp_body2))
        resp_body2 += chunk
    
    if resp_body2[0] == 0x00:
        print('PASS: Auth succeeded on second connection!')
    elif resp_body2[0] == 0xFF:
        err_code2 = struct.unpack('<H', resp_body2[1:3])[0]
        err_msg2 = resp_body2[3:].decode(errors='replace')
        print(f'FAIL: Error {err_code2}: {err_msg2}')

sock2.close()