import os
import sys
import time
import uuid
import traceback
from datetime import datetime
from concurrent.futures import Future
import paramiko
from flask_socketio import emit, disconnect
from app import db, socketio
from app.models import Asset, Credential, SessionRecord, User
from app.services.crypto_service import CryptoService
from app.services.audit_service import write_audit_log
from app.services.command_interceptor import intercept_command
from app.utils.auth import verify_token
from flask import request, current_app
from dotenv import load_dotenv
from app.utils.logger import get_logger

logger = get_logger('app.routes.ssh')

# 加载环境变量
load_dotenv()

# 确保recordings目录存在
recordings_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'recordings')
if not os.path.exists(recordings_dir):
    os.makedirs(recordings_dir)

# 存储活动的SSH连接
active_connections = {}
_pending_signatures = {}

@socketio.on('connect')
def handle_connect():
    """
    处理WebSocket连接，验证token
    """
    # 从query参数获取token
    token = request.args.get('token')
    
    if not token:
        current_app.logger.error('[SSH WS] Connection refused: No token provided')
        return False
    
    try:
        # 验证Token（支持SM2签名和HS256）
        decoded = verify_token(token)
        if not decoded:
            current_app.logger.error(f'[SSH WS] Connection refused: Invalid token, first 20 chars: {token[:20]}...')
            return False
        current_app.logger.info(f'[SSH WS] Connection authenticated: {decoded.get("username")}')
    except Exception as e:
        current_app.logger.error(f'[SSH WS] Connection refused: {str(e)}')
        return False
    
    return True

@socketio.on('disconnect')
def handle_disconnect():
    cleanup_connection(request.sid)
    try:
        from app.routes.winrm import active_connections as winrm_connections
        from app.routes.winrm import _cleanup_connection as winrm_cleanup
        for session_id, conn_info in list(winrm_connections.items()):
            if conn_info.get('sid') == request.sid:
                winrm_cleanup(session_id)
                break
    except ImportError:
        pass
    except Exception:
        pass

def _encrypt_recording_file(session_record):
    import struct
    plaintext_path = session_record.recording_path
    if not plaintext_path or not os.path.exists(plaintext_path):
        return
    if not plaintext_path.endswith('.cast'):
        return
    enc_path = plaintext_path + '.enc'
    with open(plaintext_path, 'rb') as f:
        plaintext = f.read()
    dek = os.urandom(16)
    iv, ciphertext = CryptoService.sm4_cbc_encrypt_bytes(plaintext, dek)
    encrypted_dek = CryptoService.encrypt_dek_with_master_key(dek)
    with open(enc_path, 'wb') as f:
        f.write(struct.pack('>I', len(encrypted_dek)))
        f.write(encrypted_dek)
        f.write(iv)
        f.write(ciphertext)
    os.remove(plaintext_path)
    session_record.recording_path = enc_path
    db.session.commit()

def cleanup_connection(sid):
    """清理指定sid的连接"""
    to_remove = []
    for session_id, conn_info in active_connections.items():
        if conn_info.get('sid') == sid:
            to_remove.append(session_id)
    for session_id in to_remove:
        try:
            conn_info = active_connections[session_id]
            if conn_info.get('channel'):
                conn_info['channel'].close()
            if conn_info.get('client'):
                conn_info['client'].close()
            if conn_info.get('recording_file'):
                conn_info['recording_file'].close()
            del active_connections[session_id]
            session_record = SessionRecord.query.filter_by(session_id=session_id).first()
            if session_record:
                session_record.end_time = datetime.now()
                db.session.commit()
                try:
                    _encrypt_recording_file(session_record)
                except Exception as enc_err:
                    current_app.logger.critical('[SSH WS] 录像加密失败，保留明文文件: %s', enc_err)
            current_app.logger.info(f'[SSH WS] Cleaned up session: {session_id}')
        except Exception as e:
            current_app.logger.error(f'[SSH WS] Error cleaning session {session_id}: {str(e)}')

@socketio.on('ssh_connect')
def handle_ssh_connect(data):
    """
    处理SSH连接请求
    """
    # 清理旧连接，避免冲突
    cleanup_connection(request.sid)
    
    asset_id = data.get('asset_id')
    username = data.get('username', 'root')
    current_app.logger.info(f'[WebSSH] ssh_connect called with asset_id: {asset_id}, username: {username}, sid: {request.sid}')

    if not asset_id:
        emit('error', {'message': 'Asset ID is required'})
        return
    
    # 验证用户权限（这里简化处理，实际应该检查用户是否有权访问该资产）
    # 从token中获取用户信息
    token = request.args.get('token')
    try:
        decoded = verify_token(token)
        if not decoded:
            current_app.logger.error(f'[WebSSH] Authorization failed: Invalid token')
            emit('error', {'message': 'Unauthorized access'})
            return
        user = decoded.get('username')

        login_ip = decoded.get('login_ip')
        if login_ip and login_ip != request.remote_addr:
            current_app.logger.error('[SSH WS] Connection refused: JWT IP mismatch (token: %s, request: %s)', login_ip, request.remote_addr)
            emit('error', {'message': 'Authorization failed: IP address mismatch'})
            write_audit_log(
                'JWT_IP_MISMATCH',
                operator=user or 'unknown',
                source_ip=request.remote_addr or 'unknown',
                target_asset='',
                operation_detail=f'JWT IP不匹配: token中={login_ip}, 当前请求IP={request.remote_addr}',
                result='failed'
            )
            return
        
        # 这里应该添加资产访问权限检查
        # 例如：检查用户是否有权访问该资产
        # 简化处理：假设所有登录用户都有权访问所有资产
        current_app.logger.info(f'[WebSSH] User {user} authorized to access asset {asset_id}')
    except Exception as e:
        current_app.logger.error(f'[WebSSH] Authorization failed: {str(e)}')
        emit('error', {'message': 'Unauthorized access'})
        return

    try:
        # 获取资产和凭证信息
        current_app.logger.info(f'[WebSSH] Querying database for asset {asset_id}')
        credential = Credential.query.join(Asset).filter(
            Asset.id == asset_id,
            Credential.account_name == username
        ).first()

        if not credential:
            current_app.logger.error(f'[WebSSH] Credential not found for asset_id: {asset_id}, username: {username}')
            emit('error', {'message': 'Credential not found'})
            return

        asset = credential.asset
        
        # 检查端口字段
        ssh_port = asset.ssh_port
        current_app.logger.info(f'[WebSSH] Asset details: ID={asset.id}, IP={asset.ip}, SSH Port={ssh_port}, OS Type={asset.os_type}, Status={asset.status}')
        
        # 确保端口不为空
        if not ssh_port:
            current_app.logger.error(f'[WebSSH] Asset {asset.id} has no SSH port configured')
            emit('error', {'message': 'Asset has no SSH port configured'})
            return
            
        current_app.logger.info(f'[WebSSH] Found asset: {asset.ip}:{ssh_port}')
        current_app.logger.info(f'[WebSSH] Connecting to {asset.ip}:{ssh_port} with username {username}')

        # 解密密码
        current_password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if current_password is None:
            current_app.logger.error(f'[WebSSH] Failed to decrypt password for asset_id: {asset_id}')
            emit('error', {'message': 'Failed to decrypt password'})
            return
        current_app.logger.info(f'[WebSSH] Successfully decrypted password for asset_id: {asset_id}')
        current_app.logger.info(f'[WebSSH] Password length: {len(current_password)}')

        # 生成会话ID
        session_id = str(uuid.uuid4())
        current_app.logger.info(f'[WebSSH] Generated session_id: {session_id}')

        # 创建SSH客户端连接
        current_app.logger.info(f'[WebSSH] Connecting to SSH {asset.ip}:{ssh_port}...')
        current_app.logger.info(f'[WebSSH] Connection parameters: Hostname={asset.ip}, Port={ssh_port}, Username={username}, Timeout=15 seconds')
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            start_time = time.time()
            current_app.logger.info(f'[WebSSH] SSH connection attempt started at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            
            client.connect(
                hostname=asset.ip,
                port=ssh_port,
                username=username,
                password=current_password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            connect_time = time.time() - start_time
            current_app.logger.info(f'[WebSSH] SSH connected successfully to {asset.ip}:{asset.ssh_port}')
            current_app.logger.info(f'[WebSSH] Connection time: {connect_time:.2f} seconds')
        except paramiko.AuthenticationException:
            current_app.logger.error(f'[WebSSH] Authentication failed for {asset.ip}:{asset.ssh_port}')
            emit('error', {'message': 'Authentication failed: Incorrect username or password'})
            return
        except paramiko.SSHException as e:
            current_app.logger.error(f'[WebSSH] SSH connection failed: {str(e)}')
            traceback.print_exc()
            emit('error', {'message': f'SSH connection failed: {str(e)}'})
            return
        except Exception as e:
            current_app.logger.error(f'[WebSSH] Connection error: {str(e)}')
            traceback.print_exc()
            emit('error', {'message': f'Connection failed: {str(e)}'})
            return

        # 获取交互式通道 - 指定终端类型
        channel = client.invoke_shell(term='xterm-256color', width=120, height=40)
        channel.settimeout(5.0)  # 增加超时时间
        current_app.logger.info(f'[WebSSH] Shell channel created with xterm-256color')

        # 清除内存中的明文密码
        del current_password
        import gc
        gc.collect()

        # 创建录像文件
        recording_filename = f"{asset_id}_{decoded.get('user_id')}_{session_id}.cast"
        recording_path = os.path.join(recordings_dir, recording_filename)
        recording_file = open(recording_path, 'w', encoding='utf-8')

        # 写入asciinema cast v2格式头部
        initial_timestamp = time.time()
        cast_header = {
            "version": 2,
            "width": 120,
            "height": 40,
            "timestamp": int(initial_timestamp)
        }
        import json
        header_line = json.dumps(cast_header, separators=(',', ':')) + '\n'
        recording_file.write(header_line)
        recording_file.flush()

        # 存储连接信息
        active_connections[session_id] = {
            'sid': request.sid,
            'client': client,
            'channel': channel,
            'recording_file': recording_file,
            'asset_id': asset_id,
            'user_id': decoded.get('user_id'),
            'username': decoded.get('username', 'unknown'),
            'asset_ip': asset.ip,
            'asset_port': ssh_port,
            'initial_timestamp': initial_timestamp
        }
        current_app.logger.info(f'[WebSSH] Stored connection for session_id: {session_id}')

        # 创建会话记录
        session_record = SessionRecord(
            asset_id=asset_id,
            session_id=session_id,
            recording_path=recording_path,
            user_id=decoded.get('user_id', 1),
            operator_name=decoded.get('username', 'unknown')
        )
        db.session.add(session_record)

        # 记录审计日志 - 会话开始
        write_audit_log(
            'SESSION_START',
            operator=decoded.get('username', 'unknown'),
            source_ip=request.remote_addr or 'unknown',
            target_asset=f"{asset.hostname}({asset.ip}:{ssh_port})",
            result='success',
            operation_detail=f"会话{session_id}开始 - {asset.os_type}资产",
        )

        # 更新资产最后代理登录时间
        asset.last_agent_login_time = datetime.now()

        db.session.commit()
        current_app.logger.info(f'[WebSSH] Session record created in database')
        current_app.logger.info(f'[WebSSH] Updated asset.last_agent_login_time = {asset.last_agent_login_time}')

        # 发送连接成功消息
        emit('ssh_connected', {'session_id': session_id})
        current_app.logger.info(f'[WebSSH] Sent ssh_connected event to client')

        # 主动读取初始欢迎信息
        time.sleep(1.0)  # 等待服务器发送初始数据
        try:
            current_app.logger.info(f'[WebSSH] Reading initial welcome message...')
            initial_output = b''
            start_time = time.time()
            while time.time() - start_time < 3.0:  # 最多等待3秒
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if chunk:
                        initial_output += chunk
                    else:
                        break
                else:
                    time.sleep(0.1)
            
            if initial_output:
                initial_output_str = initial_output.decode('utf-8', errors='ignore')
                current_app.logger.info(f'[WebSSH] Initial output received, length={len(initial_output_str)}')
                socketio.emit('ssh_output', {'output': initial_output_str}, room=request.sid)
                # 写入asciinema格式
                import json
                time_diff = round(time.time() - initial_timestamp, 6)
                # 使用 json.dumps 自动转义输出内容
                output_data = [time_diff, initial_output_str]
                line = json.dumps(output_data, separators=(',', ':'), ensure_ascii=False) + '\n'
                recording_file.write(line)
                recording_file.flush()
            else:
                current_app.logger.info(f'[WebSSH] No initial output received, sending prompt')
                # 发送一个空的输出以触发前端显示提示符
                socketio.emit('ssh_output', {'output': ''}, room=request.sid)
        except Exception as e:
            current_app.logger.error(f'[WebSSH] Error reading initial output: {str(e)}')
            traceback.print_exc()

        # 启动后台线程读取SSH输出
        import threading
        threading.Thread(target=read_ssh_output, args=(session_id,), daemon=True).start()
        current_app.logger.info(f'[WebSSH] Started output reader thread')

    except Exception as e:
        current_app.logger.error(f'[WebSSH] SSH connection error: {str(e)}')
        traceback.print_exc()
        emit('error', {'message': f'Connection failed: {str(e)}'})

@socketio.on('ssh_input')
def handle_ssh_input(data):
    """
    处理用户输入
    """
    session_id = data.get('session_id')
    input_data = data.get('input')

    current_app.logger.info(f'[SSH WS] Received input for session {session_id}: {repr(input_data)}')

    if not session_id:
        return

    conn_info = active_connections.get(session_id)
    if not conn_info:
        current_app.logger.error(f'[SSH WS] Session not found: {session_id}')
        return

    try:
        conn_info['channel'].send(input_data)

        # 不再将输入写入 cast 文件，asciinema 格式只记录输出
        # timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # conn_info['recording_file'].write(f"[{timestamp}] [I] {input_data}\n")
        # conn_info['recording_file'].flush()
    except Exception as e:
        current_app.logger.error(f'[SSH WS] Error sending input: {str(e)}')
        traceback.print_exc()

@socketio.on('ssh_resize')
def handle_ssh_resize(data):
    """
    处理终端窗口大小调整
    """
    session_id = data.get('session_id')
    rows = data.get('rows')
    cols = data.get('cols')

    if not session_id or rows is None or cols is None:
        return

    conn_info = active_connections.get(session_id)
    if not conn_info:
        return

    try:
        conn_info['channel'].resize_pty(width=cols, height=rows)
        current_app.logger.info(f'[SSH WS] Resized terminal to {cols}x{rows}')
    except Exception as e:
        current_app.logger.error(f'[SSH WS] Error resizing terminal: {str(e)}')


@socketio.on('dangerous_command_signature')
def handle_dangerous_command_signature(data):
    nonce = data.get('nonce')
    future = _pending_signatures.get(nonce)
    if future:
        future.set_result(data)


@socketio.on('command')
def handle_command(data):
    session_id = data.get('session_id')
    cmd = data.get('cmd', '').strip()

    conn_info = active_connections.get(session_id)
    if not conn_info:
        emit('error', {'message': 'Session not found'}, room=request.sid)
        return

    blocked, rule_name, _ = intercept_command(cmd)
    if blocked:
        nonce = os.urandom(16).hex()
        timestamp = int(time.time())
        challenge_data = {
            'command': cmd,
            'asset_id': conn_info.get('asset_id'),
            'timestamp': timestamp,
            'nonce': nonce
        }

        future = Future()
        _pending_signatures[nonce] = future

        emit('dangerous_command_challenge', {
            'challenge': challenge_data
        }, room=request.sid)

        try:
            result = future.result(timeout=30)
        except TimeoutError:
            _pending_signatures.pop(nonce, None)
            emit('ssh_output', {
                'output': '# PAM SECURITY: 签名超时，命令已被拒绝执行\n'
            }, room=request.sid)
            write_audit_log(
                'COMMAND_SIGN_FAILED',
                operator=conn_info.get('username', 'unknown'),
                source_ip=request.remote_addr or 'unknown',
                target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
                operation_detail=f'高危命令签名超时: {cmd} (规则: {rule_name})',
                result='failed'
            )
            return
        finally:
            _pending_signatures.pop(nonce, None)

        if result.get('cancelled'):
            emit('ssh_output', {
                'output': '# PAM SECURITY: 用户取消签名，命令已被拒绝执行\n'
            }, room=request.sid)
            write_audit_log(
                'COMMAND_SIGN_FAILED',
                operator=conn_info.get('username', 'unknown'),
                source_ip=request.remote_addr or 'unknown',
                target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
                operation_detail=f'高危命令签名取消: {cmd} (规则: {rule_name})',
                result='cancelled'
            )
            return

        signature = result.get('signature', '')
        user_id = conn_info.get('user_id')
        user = User.query.get(user_id)
        if not user or not user.sm2_public_key:
            emit('ssh_output', {
                'output': '# PAM SECURITY: 用户未配置SM2公钥，无法验签\n'
            }, room=request.sid)
            write_audit_log(
                'COMMAND_SIGN_FAILED',
                operator=conn_info.get('username', 'unknown'),
                source_ip=request.remote_addr or 'unknown',
                target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
                operation_detail=f'高危命令验签失败: 用户无SM2公钥 (规则: {rule_name})',
                result='failed'
            )
            return

        import json
        challenge_str = json.dumps(challenge_data, separators=(',', ':'))
        valid = CryptoService.sm2_verify_with_public_key(challenge_str, signature, user.sm2_public_key)
        if not valid:
            emit('ssh_output', {
                'output': '# PAM SECURITY: 签名验证失败，命令已被拒绝执行\n'
            }, room=request.sid)
            write_audit_log(
                'COMMAND_SIGN_FAILED',
                operator=conn_info.get('username', 'unknown'),
                source_ip=request.remote_addr or 'unknown',
                target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
                operation_detail=f'高危命令验签失败: {cmd} (规则: {rule_name})',
                result='failed'
            )
            return

        write_audit_log(
            'COMMAND_EXEC_SIGNED',
            operator=conn_info.get('username', 'unknown'),
            source_ip=request.remote_addr or 'unknown',
            target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
            operation_detail=f'高危命令已签名确认并执行: {cmd} (规则: {rule_name})',
            result='success'
        )

    conn_info['channel'].send(cmd + '\n')

def read_ssh_output(session_id):
    """
    读取SSH输出并发送到前端
    """
    logger.info(f'[SSH WS] Output reader started for session: {session_id}')

    while True:
        conn_info = active_connections.get(session_id)
        if not conn_info:
            logger.info(f'[SSH WS] Session ended: {session_id}')
            break

        channel = conn_info['channel']
        if not channel:
            logger.info(f'[SSH WS] Channel closed for session: {session_id}')
            break

        if channel.closed:
            logger.info(f'[SSH WS] Channel closed by server for session: {session_id}')
            break

        try:
            if channel.recv_ready():
                output = channel.recv(65535).decode('utf-8', errors='ignore')
                if output:
                    logger.debug(f'[SSH WS] Sending output ({len(output)} bytes) to session: {session_id}')
                    socketio.emit('ssh_output', {'output': output}, room=conn_info['sid'])

                    # 写入asciinema格式
                    import json
                    initial_timestamp = conn_info.get('initial_timestamp', time.time())
                    time_diff = round(time.time() - initial_timestamp, 6)
                    # 使用 json.dumps 自动转义输出内容
                    output_data = [time_diff, output]
                    line = json.dumps(output_data, separators=(',', ':'), ensure_ascii=False) + '\n'
                    conn_info['recording_file'].write(line)
                    conn_info['recording_file'].flush()
            else:
                time.sleep(0.01)
        except Exception as e:
            logger.error(f'[SSH WS] Error reading output: {str(e)}', exc_info=True)
            break

    logger.info(f'[SSH WS] Output reader stopped for session: {session_id}')