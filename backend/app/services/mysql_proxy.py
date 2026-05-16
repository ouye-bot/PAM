import sys
import os
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import threading
import time
import re
import uuid
import struct
import sqlparse
import socketserver
import socket
import pymysql
import pymysql.cursors
from dbutils.pooled_db import PooledDB
from flask import current_app
from app.utils.logger import get_logger
logger = get_logger('app.services.mysql_proxy')

TOKEN_EXPIRY_SECONDS = 300

token_cache = {}
token_cache_lock = threading.Lock()

_db_pool = None
_pool_lock = threading.Lock()

def get_db_pool():
    global _db_pool
    if _db_pool is None:
        with _pool_lock:
            if _db_pool is None:
                _db_pool = PooledDB(
                    creator=pymysql,
                    maxconnections=20,
                    mincached=5,
                    maxcached=20,
                    blocking=True,
                    maxusage=None,
                    setsession=[],
                    ping=0,
                    host=current_app.config.get('DB_HOST', '127.0.0.1'),
                    port=current_app.config.get('DB_PORT', 3306),
                    user=current_app.config.get('DB_USER', 'root'),
                    password=current_app.config.get('DB_PASSWORD', ''),
                    database=current_app.config.get('DB_NAME', 'pam_db'),
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor
                )
                logger.info("数据库连接池初始化成功")
    return _db_pool

def generate_token(asset_id=None, source_ip='', username='', password='', key_version=None, host='', port=3306, **kwargs):
    import uuid
    token = str(uuid.uuid4()).replace('-', '') + str(uuid.uuid4()).replace('-', '')
    token_data = {
        'token': token,
        'asset_id': asset_id,
        'source_ip': source_ip,
        'username': username,
        'password': password,
        'key_version': key_version,
        'host': host,
        'port': port,
        'created_at': time.time(),
        'expires_at': time.time() + TOKEN_EXPIRY_SECONDS
    }
    token_data.update(kwargs)
    with token_cache_lock:
        token_cache[token] = token_data
    logger.debug(f"Token generated: {token[:8]}...")
    return token

def validate_token(token):
    with token_cache_lock:
        if token not in token_cache:
            return None
        token_info = token_cache[token]
        if time.time() > token_info['expires_at']:
            del token_cache[token]
            return None
        return token_info


import hashlib

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def validate_token_by_auth(scramble, auth_resp):
    if len(auth_resp) != 20:
        return None
    with token_cache_lock:
        now = time.time()
        expired = []
        for token, token_info in token_cache.items():
            if now > token_info.get('expires_at', 0):
                expired.append(token)
                continue
            token_bytes = token.encode()
            stage1 = hashlib.sha1(token_bytes).digest()
            stage2 = hashlib.sha1(stage1).digest()
            expected = xor_bytes(stage1, hashlib.sha1(scramble + stage2).digest())
            if expected == auth_resp:
                return token_info
        for t in expired:
            del token_cache[t]
    return None

def add_token(asset_id, source_ip, username, token):
    token_data = {
        'asset_id': asset_id,
        'source_ip': source_ip,
        'username': username,
        'token': token,
        'created_at': time.time(),
        'expires_at': time.time() + TOKEN_EXPIRY_SECONDS
    }
    with token_cache_lock:
        token_cache[token] = token_data
    return token

def cleanup_expired_tokens():
    now = time.time()
    removed = 0
    with token_cache_lock:
        expired = [t for t, info in token_cache.items() if now > info.get('expires_at', 0)]
        for t in expired:
            del token_cache[t]
            removed += 1
    if removed > 0:
        logger.info(f"Cleaned {removed} expired token(s) from cache")

def start_token_cleanup_thread(interval=60):
    def _cleanup_loop():
        while True:
            time.sleep(interval)
            try:
                cleanup_expired_tokens()
            except Exception as e:
                logger.error("Token cleanup error: %s", e)
    t = threading.Thread(target=_cleanup_loop, daemon=True, name='token-cleanup')
    t.start()
    logger.info("Token cleanup thread started (interval=%ds)", interval)

# ============================================================
# 第一阶段：高危SQL检测
# ============================================================

def is_dangerous_sql(sql):
    if not sql or not isinstance(sql, str):
        return False
    try:
        parsed = sqlparse.parse(sql)
        if not parsed:
            return _fallback_regex_detect(sql)
        stmt = parsed[0]
        tokens = [tok for tok in stmt.tokens if not tok.is_whitespace]
        stmt_type = stmt.get_type().upper() if stmt.get_type() else ''

        stmt_value_upper = stmt.value.strip().upper() if stmt.value else ''

        if 'DROP' in stmt_type or 'DROP' in stmt_value_upper:
            for i, tok in enumerate(tokens):
                if tok.value.upper() == 'DROP':
                    for j in range(i + 1, len(tokens)):
                        if tokens[j].value.upper() == 'DATABASE':
                            return True
                    break
            return False

        if 'TRUNCATE' in stmt_type or 'TRUNCATE' in stmt_value_upper:
            return True

        if 'DELETE' in stmt_type or 'DELETE' in stmt_value_upper:
            has_where = any(tok.value.upper() == 'WHERE' for tok in tokens)
            has_limit = any(tok.value.upper() == 'LIMIT' for tok in tokens)
            if not has_where and not has_limit:
                return True

        return False
    except Exception:
        return _fallback_regex_detect(sql)

def _fallback_regex_detect(sql):
    if not sql or not isinstance(sql, str):
        return False
    sql_stripped = sql.strip()
    if re.search(r'DROP\s+DATABASE', sql_stripped, re.IGNORECASE):
        return True
    if re.search(r'TRUNCATE\s+(TABLE\s+)?', sql_stripped, re.IGNORECASE):
        return True
    if re.search(r'DELETE\s+FROM', sql_stripped, re.IGNORECASE):
        has_where = re.search(r'\bWHERE\b', sql_stripped, re.IGNORECASE)
        has_limit = re.search(r'\bLIMIT\b', sql_stripped, re.IGNORECASE)
        if not has_where and not has_limit:
            return True
    return False

# 向后兼容：proxy.py 中 intercept_sql 返回 (blocked, reason) 元组
def intercept_sql(sql):
    if is_dangerous_sql(sql):
        return True, '高危SQL被拦截'
    return False, ''

def write_audit_log(log_type, **kwargs):
    from app.services.audit_service import write_audit_log as real_audit
    try:
        operator = kwargs.get('operator', 'system')
        source_ip = kwargs.get('source_ip', '127.0.0.1')
        target_asset = kwargs.get('target_asset', kwargs.get('asset', 'unknown'))
        operation_detail = kwargs.get('operation_detail', kwargs.get('detail', str(kwargs)))
        result = kwargs.get('result', 'success')
        real_audit(
            log_type=log_type,
            operator=operator,
            source_ip=source_ip,
            target_asset=target_asset,
            operation_detail=operation_detail,
            result=result
        )
    except Exception as e:
        logger.warning(f"[AUDIT_FALLBACK] {log_type}: {kwargs} (audit_service error: {e})")
    logger.info(f"[AUDIT] {log_type}: {kwargs}")

# ============================================================
# 第二阶段：MySQL协议握手 + TCP监听框架
# ============================================================

CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_BASIC_FLAGS = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH

def generate_handshake_packet():
    connection_id = 1
    scramble = os.urandom(20)
    scramble_part1 = scramble[:8]
    scramble_part2 = scramble[8:20]

    payload = bytearray()
    payload.append(10)  # 协议版本
    payload.extend(b'5.7.0-pam-proxy\x00')  # 服务器版本
    payload.extend(struct.pack('<I', connection_id))  # 连接ID
    payload.extend(scramble_part1)  # auth plugin data part1
    payload.append(0x00)  # filler
    payload.extend(struct.pack('<H', CLIENT_BASIC_FLAGS & 0xFFFF))  # 能力标志低16位
    payload.append(33)  # utf8字符集
    payload.extend(struct.pack('<H', 0x0002))  # 状态标志 (SERVER_STATUS_AUTOCOMMIT)
    payload.extend(struct.pack('<H', (CLIENT_BASIC_FLAGS >> 16) & 0xFFFF))  # 能力标志高16位
    payload.append(8 + 12 + 1)  # auth_plugin_data_len (part1 + part2 + null)
    payload.extend(b'\x00' * 10)  # 保留位
    payload.extend(scramble_part2)  # auth plugin data part2
    payload.append(0x00)  # null终止
    payload.extend(b'mysql_native_password\x00')  # 认证插件名
    return bytes(payload), scramble

def pack_mysql_packet(sequence_id, payload):
    length = len(payload)
    header = bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, sequence_id])
    return header + payload

def build_error_packet(sequence_id, error_code, message):
    payload = bytearray()
    payload.append(0xFF)
    payload.extend(struct.pack('<H', error_code))
    payload.extend(b'#')
    payload.extend(b'28000')
    payload.extend(message.encode('utf-8'))
    return pack_mysql_packet(sequence_id, bytes(payload))

def build_ok_packet(sequence_id, affected_rows=0, last_insert_id=0):
    payload = bytearray()
    payload.append(0x00)
    if affected_rows < 251:
        payload.append(affected_rows & 0xFF)
    else:
        payload.append(0xFA)
        payload.extend(struct.pack('<I', affected_rows))
    if last_insert_id < 251:
        payload.append(last_insert_id & 0xFF)
    else:
        payload.append(0xFA)
        payload.extend(struct.pack('<I', last_insert_id))
    payload.extend(struct.pack('<H', 0x0002))
    payload.extend(struct.pack('<H', 0))
    return pack_mysql_packet(sequence_id, bytes(payload))

def build_column_definition(sequence_id, column_name, column_type=253):
    payload = bytearray()
    payload.extend(b'\x03def')
    payload.append(0x00)
    payload.append(0x00)
    payload.append(0x00)
    name_bytes = column_name.encode('utf-8') if isinstance(column_name, str) else column_name
    payload.append(len(name_bytes))
    payload.extend(name_bytes)
    payload.append(0x00)
    payload.append(0x0c)
    payload.extend(struct.pack('<H', 33))
    payload.extend(struct.pack('<I', 255))
    payload.append(column_type)
    payload.extend(struct.pack('<H', 0))
    payload.append(0)
    payload.extend(struct.pack('<H', 0))
    return pack_mysql_packet(sequence_id, bytes(payload))

def build_result_set(start_sequence_id, cursor):
    packets = []
    seq = start_sequence_id
    columns = cursor.description
    num_columns = len(columns)
    col_count_payload = bytes([num_columns])
    packets.append(pack_mysql_packet(seq, col_count_payload))
    seq += 1
    for col in columns:
        col_name = col[0]
        col_type = col[1] if len(col) > 1 else 253
        packets.append(build_column_definition(seq, col_name, col_type))
        seq += 1
    eof_payload = b'\xFE\x00\x00\x02\x00'
    packets.append(pack_mysql_packet(seq, eof_payload))
    seq += 1
    for row in cursor:
        row_payload = bytearray()
        for value in row:
            if value is None:
                row_payload.append(0xFB)
            else:
                if isinstance(value, bytes):
                    val_bytes = value
                elif isinstance(value, str):
                    val_bytes = value.encode('utf-8')
                else:
                    val_bytes = str(value).encode('utf-8')
                if len(val_bytes) < 251:
                    row_payload.append(len(val_bytes))
                else:
                    row_payload.extend(b'\xFB')
                    row_payload.extend(struct.pack('<H', len(val_bytes)))
                row_payload.extend(val_bytes)
        packets.append(pack_mysql_packet(seq, bytes(row_payload)))
        seq += 1
    eof2_payload = b'\xFE\x00\x00\x02\x00'
    packets.append(pack_mysql_packet(seq, eof2_payload))
    seq += 1
    return packets, seq

class MySQLProxyHandler(socketserver.BaseRequestHandler):
    flask_app = None

    def handle(self):
        logger.info(f"[PROXY] 新连接: {self.client_address}")
        write_audit_log('MYSQL_PROXY_CONNECT', operator='system', source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset='mysql_proxy', operation_detail=f'客户端连接: {self.client_address}', result='success')
        self.request.settimeout(10)
        try:
            handshake_payload, self.scramble = generate_handshake_packet()
            self.request.sendall(pack_mysql_packet(0, handshake_payload))
            logger.debug(f"[PROXY] 已发送握手包 (scramble={self.scramble.hex()})")

            header = self.request.recv(4)
            if len(header) < 4:
                logger.warning("[PROXY] 客户端过早断开")
                return
            payload_len = header[0] | (header[1] << 8) | (header[2] << 16)
            seq_id = header[3]
            payload = b''
            while len(payload) < payload_len:
                chunk = self.request.recv(payload_len - len(payload))
                if not chunk:
                    break
                payload += chunk
            logger.debug(f"[PROXY] 收到认证包: seq_id={seq_id}, len={payload_len}")

            offset = 0
            offset += 4
            offset += 4
            offset += 1
            offset += 23
            null_pos = payload.find(b'\x00', offset)
            if null_pos < 0:
                logger.error("[PROXY] 无法解析用户名")
                self.request.close()
                return
            username = payload[offset:null_pos].decode('utf-8', errors='replace')
            offset = null_pos + 1
            auth_resp_len = payload[offset]
            offset += 1
            auth_resp = payload[offset:offset + auth_resp_len]

            logger.debug(f"[PROXY] 收到认证: username={username}, auth_resp_len={auth_resp_len}")

            token_info = validate_token_by_auth(self.scramble, auth_resp)
            if token_info is None:
                logger.warning(f"[PROXY] Token验证失败: token_cache_size={len(token_cache)}")
                error_pkt = build_error_packet(2, 1045, "Access denied: invalid token")
                self.request.sendall(error_pkt)
                write_audit_log('MYSQL_PROXY_AUTH_FAIL', operator=username, source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset='mysql_proxy', operation_detail=f'认证失败 - username={username}, 原因=无效Token', result='failure')
                self.request.close()
                logger.info(f"[PROXY] 连接关闭: {self.client_address}")
                return

            logger.info(f"[PROXY] Token有效: username={token_info.get('username', username)}")
            self.authenticated_username = token_info.get('username', username)
            self.token_info = token_info

            self._handle_authenticated()

        except socket.timeout:
            logger.warning(f"[PROXY] 客户端认证超时，连接关闭: {self.client_address}")
            write_audit_log('MYSQL_PROXY_TIMEOUT', operator='system',
                           source_ip=self.client_address[0] if self.client_address else 'unknown',
                           target_asset='mysql_proxy',
                           operation_detail='客户端认证超时(10秒)，连接关闭',
                           result='timeout')
        except Exception as e:
            logger.error(f"[PROXY] 处理异常: {e}")
            try:
                error_pkt = build_error_packet(2, 1045, f"Authentication error: {e}")
                self.request.sendall(error_pkt)
            except:
                pass
        finally:
            try:
                self.request.close()
                logger.info(f"[PROXY] 连接关闭: {self.client_address}")
            except:
                pass

    def _handle_authenticated(self):
        username = self.token_info.get('username', self.authenticated_username)
        encrypted_password = self.token_info.get('password', '')
        key_version = self.token_info.get('key_version')
        host = self.token_info.get('host', '127.0.0.1')
        port = self.token_info.get('port', 3306)

        try:
            from app.services.crypto_service import CryptoService
            app = self.__class__.flask_app
            if app:
                with app.app_context():
                    password = CryptoService.sm4_decrypt(encrypted_password, key_version)
            else:
                password = encrypted_password
            if not password:
                raise Exception("credential decryption failed")
            logger.info(f"[PROXY] 连接后端MySQL: {host}:{port}/{username}")
            self.backend_conn = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                autocommit=True
            )
            logger.info(f"[PROXY] 后端MySQL连接成功")
            self.request.settimeout(300)
            write_audit_log('MYSQL_PROXY_AUTH_SUCCESS', operator=username, source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset=f'mysql_proxy/{host}:{port}', operation_detail=f'代理认证成功 - username={username}', result='success')
            ok_pkt = build_ok_packet(2)
            self.request.sendall(ok_pkt)
            self._sql_forward_loop()
        except pymysql.err.OperationalError as e:
            error_msg = str(e)
            logger.error(f"[PROXY] 后端MySQL连接失败: {error_msg}")
            write_audit_log('MYSQL_PROXY_AUTH_FAIL', operator=username, source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset=f'mysql_proxy/{host}:{port}', operation_detail=f'后端连接失败', result='failure')
            error_pkt = build_error_packet(2, 1045, error_msg)
            self.request.sendall(error_pkt)
            self.request.close()
        except Exception as e:
            error_msg = str(e)
            logger.error(f"[PROXY] _handle_authenticated异常")
            error_pkt = build_error_packet(2, 1045, f"Connection failed")
            try:
                self.request.sendall(error_pkt)
            except:
                pass
            self.request.close()

    def _sql_forward_loop(self):
        logger.info("[PROXY] SQL转发循环启动")
        try:
            self.backend_cursor = self.backend_conn.cursor(pymysql.cursors.Cursor)
            while True:
                header = self.request.recv(4)
                if len(header) < 4:
                    break
                payload_len = header[0] | (header[1] << 8) | (header[2] << 16)
                seq_id = header[3]
                payload = b''
                while len(payload) < payload_len:
                    chunk = self.request.recv(payload_len - len(payload))
                    if not chunk:
                        break
                    payload += chunk
                if not payload:
                    break
                command_type = payload[0]
                if command_type == 0x01:
                    logger.info("[PROXY] 客户端发送COM_QUIT，关闭连接")
                    break
                elif command_type == 0x02:
                    db_name = payload[1:].decode('utf-8', errors='replace')
                    logger.info(f"[PROXY] COM_INIT_DB: {db_name}")
                    try:
                        self.backend_cursor.execute(f"USE `{db_name}`")
                        ok_pkt = build_ok_packet(seq_id + 1, 0, 0)
                        self.request.sendall(ok_pkt)
                    except pymysql.err.Error as e:
                        err_code = getattr(e, 'args', (0, ''))
                        if isinstance(err_code, tuple) and len(err_code) > 1:
                            mysql_errno = err_code[0] if isinstance(err_code[0], int) else 1049
                            mysql_msg = str(err_code[1])
                        else:
                            mysql_errno = 1049
                            mysql_msg = str(e)
                        error_pkt = build_error_packet(seq_id + 1, mysql_errno, mysql_msg)
                        self.request.sendall(error_pkt)
                elif command_type == 0x03:
                    sql = payload[1:].decode('utf-8', errors='replace')
                    username = getattr(self, 'authenticated_username', 'unknown')
                    if is_dangerous_sql(sql):
                        write_audit_log('MYSQL_PROXY_SQL_DENY', operator=username, source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset=f'mysql_proxy', operation_detail=f'高危SQL拦截 - sql={sql}', result='denied')
                        error_pkt = build_error_packet(
                            seq_id + 1, 1142,
                            "Command denied by PAM proxy"
                        )
                        self.request.sendall(error_pkt)
                        continue
                    try:
                        self.backend_cursor.execute(sql)
                        if self.backend_cursor.description:
                            result_packets, _ = build_result_set(seq_id + 1, self.backend_cursor)
                            for pkt in result_packets:
                                self.request.sendall(pkt)
                        else:
                            ok_pkt = build_ok_packet(
                                seq_id + 1,
                                self.backend_cursor.rowcount,
                                0
                            )
                            self.request.sendall(ok_pkt)
                    except pymysql.err.Error as e:
                        err_code = getattr(e, 'args', (0, ''))
                        if isinstance(err_code, tuple) and len(err_code) > 1:
                            mysql_errno = err_code[0] if isinstance(err_code[0], int) else 1064
                            mysql_msg = str(err_code[1])
                        else:
                            mysql_errno = 1064
                            mysql_msg = str(e)
                        write_audit_log('MYSQL_PROXY_SQL_ERROR', operator=username, source_ip=self.client_address[0] if self.client_address else 'unknown', target_asset=f'mysql_proxy', operation_detail=f'SQL执行异常 - sql={sql}, err={mysql_msg}', result='failure')
                        error_pkt = build_error_packet(seq_id + 1, mysql_errno, mysql_msg)
                        self.request.sendall(error_pkt)
                else:
                    ok_pkt = build_ok_packet(seq_id + 1, 0, 0)
                    self.request.sendall(ok_pkt)
        except Exception as e:
            logger.error(f"[PROXY] SQL转发异常: {e}")
        finally:
            try:
                self.backend_cursor.close()
            except:
                pass
            try:
                self.backend_conn.close()
            except:
                pass
            logger.info("[PROXY] 后端MySQL连接已关闭")

def start_proxy_server(host='127.0.0.1', port=3307, flask_app=None):
    if flask_app:
        MySQLProxyHandler.flask_app = flask_app
    server = socketserver.ThreadingTCPServer((host, port), MySQLProxyHandler)
    server.allow_reuse_address = True
    logger.info(f"[PROXY] MySQL代理启动: {host}:{port}")
    logger.info(f"[PROXY] 后端MySQL: 127.0.0.1:3306")
    logger.info(f"[PROXY] 等待客户端连接...")
    server.serve_forever()

if __name__ == '__main__':
    start_proxy_server()
