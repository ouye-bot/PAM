import os
import json
import time
import uuid
import struct
import threading
from datetime import datetime
from concurrent.futures import Future
import winrm
from flask_socketio import emit, disconnect
from flask import request, current_app
from app import db, socketio
from app.models import Asset, Credential, SessionRecord, User
from app.services.crypto_service import CryptoService
from app.services.audit_service import write_audit_log
from app.services.command_interceptor import intercept_command
from app.utils.auth import verify_token
from app.utils.logger import get_logger

logger = get_logger('app.routes.winrm')

recordings_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'recordings')
if not os.path.exists(recordings_dir):
    os.makedirs(recordings_dir)

active_connections = {}
_pending_signatures = {}


def _encrypt_recording_file(session_record):
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


def _cleanup_connection(session_id):
    conn_info = active_connections.pop(session_id, None)
    if not conn_info:
        return

    try:
        if conn_info.get('shell_id') and conn_info.get('protocol'):
            try:
                kill_cmd = "Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $pid } | ForEach-Object { taskkill /F /PID $_.ProcessId } 2>$null"
                conn_info['protocol'].run_command(conn_info['shell_id'], kill_cmd)
            except:
                pass
            try:
                conn_info['protocol'].close_shell(conn_info['shell_id'])
            except Exception as e:
                logger.error('[WINRM WS] Error closing shell: %s', e)
        if conn_info.get('protocol'):
            try:
                pass
            except Exception as e:
                logger.error('[WINRM WS] Error closing protocol: %s', e)
        if conn_info.get('recording_file'):
            conn_info['recording_file'].close()
    except Exception as e:
        logger.error('[WINRM WS] Error during cleanup: %s', e)

    session_record = SessionRecord.query.filter_by(session_id=session_id).first()
    if session_record:
        session_record.end_time = datetime.now()
        db.session.commit()
        try:
            _encrypt_recording_file(session_record)
        except Exception as enc_err:
            current_app.logger.critical('[WINRM WS] Recording encryption failed: %s', enc_err)

    if conn_info.get('idle_timer'):
        conn_info['idle_timer'].cancel()


@socketio.on('winrm_connect')
def handle_winrm_connect(data):
    token = request.args.get('token')
    if not token:
        current_app.logger.error('[WINRM WS] Connection refused: No token provided')
        emit('error', {'message': 'Authorization failed: No token'}, room=request.sid)
        return

    try:
        decoded = verify_token(token)
        if not decoded:
            current_app.logger.error('[WINRM WS] Connection refused: Invalid token')
            emit('error', {'message': 'Authorization failed: Invalid token'}, room=request.sid)
            return

        login_ip = decoded.get('login_ip')
        if login_ip and login_ip != request.remote_addr:
            current_app.logger.error('[WINRM WS] Connection refused: JWT IP mismatch (token: %s, request: %s)', login_ip, request.remote_addr)
            emit('error', {'message': 'Authorization failed: IP address mismatch'}, room=request.sid)
            write_audit_log(
                'JWT_IP_MISMATCH',
                operator=decoded.get('username', 'unknown'),
                source_ip=request.remote_addr or 'unknown',
                target_asset='',
                operation_detail=f'JWT IP不匹配: token中={login_ip}, 当前请求IP={request.remote_addr}',
                result='failed'
            )
            return
    except Exception as e:
        current_app.logger.error('[WINRM WS] Connection refused: %s', str(e))
        emit('error', {'message': f'Authorization failed: {str(e)}'}, room=request.sid)
        return

    asset_id = data.get('asset_id')
    if not asset_id:
        current_app.logger.error('[WINRM WS] Connection refused: No asset_id')
        emit('error', {'message': 'Asset ID is required'}, room=request.sid)
        return

    try:
        asset_id = int(asset_id)
    except ValueError:
        current_app.logger.error('[WINRM WS] Connection refused: Invalid asset_id')
        emit('error', {'message': 'Invalid asset ID'}, room=request.sid)
        return

    asset = Asset.query.get(asset_id)
    if not asset or asset.status == 'deleted':
        current_app.logger.error('[WINRM WS] Connection refused: Asset not found or deleted')
        emit('error', {'message': 'Asset not found'}, room=request.sid)
        return

    if not asset.os_type or asset.os_type.lower() != 'windows':
        current_app.logger.error('[WINRM WS] Connection refused: Asset is not Windows type')
        emit('error', {'message': 'Asset is not Windows type'}, room=request.sid)
        return

    credential = Credential.query.filter_by(asset_id=asset_id).first()
    if not credential:
        current_app.logger.error('[WINRM WS] Connection refused: No credential found')
        emit('error', {'message': 'No credential configured for this asset'}, room=request.sid)
        return

    password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
    if password is None:
        current_app.logger.error('[WINRM WS] Connection refused: Password decryption failed')
        emit('error', {'message': 'Password decryption failed'}, room=request.sid)
        return

    try:
        protocol = winrm.Protocol(
            endpoint=f'http://{asset.ip}:{asset.ssh_port}/wsman',
            transport='ntlm',
            username=credential.account_name,
            password=password,
            operation_timeout_sec=30,
            read_timeout_sec=35
        )
        shell_id = protocol.open_shell()

        auto_cmd = "$ConfirmPreference = 'None'; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8"
        result = protocol.run_command(shell_id, auto_cmd)
        protocol.cleanup_command(shell_id, result)

    except Exception as e:
        current_app.logger.error('[WINRM WS] WinRM connection failed: %s', str(e))
        emit('error', {'message': f'WinRM connection failed: {str(e)}'}, room=request.sid)
        return
    finally:
        del password
        import gc
        gc.collect()

    session_id = str(uuid.uuid4())
    recording_filename = f"{asset_id}_{decoded.get('user_id')}_{session_id}.cast"
    recording_path = os.path.join(recordings_dir, recording_filename)
    recording_file = open(recording_path, 'w', encoding='utf-8')

    initial_timestamp = time.time()
    cast_header = {
        "version": 2,
        "width": 120,
        "height": 40,
        "timestamp": int(initial_timestamp)
    }
    header_line = json.dumps(cast_header, separators=(',', ':')) + '\n'
    recording_file.write(header_line)
    recording_file.flush()

    user_id = decoded.get('user_id')
    username = decoded.get('username', 'unknown')

    session_record = SessionRecord(
        asset_id=asset_id,
        session_id=session_id,
        recording_path=recording_path,
        user_id=user_id,
        operator_name=username
    )
    db.session.add(session_record)
    db.session.commit()

    idle_timer = threading.Timer(1800.0, _idle_timeout, args=[session_id])
    idle_timer.daemon = True
    idle_timer.start()

    active_connections[session_id] = {
        'sid': request.sid,
        'protocol': protocol,
        'shell_id': shell_id,
        'recording_file': recording_file,
        'asset_id': asset_id,
        'user_id': user_id,
        'username': username,
        'initial_timestamp': initial_timestamp,
        'asset_ip': asset.ip,
        'asset_port': asset.ssh_port,
        'idle_timer': idle_timer,
        'last_activity': time.time()
    }

    current_app.logger.info('[WINRM WS] Session %s established for user %s on asset %s', session_id, username, asset_id)

    emit('winrm_connected', {
        'session_id': session_id
    }, room=request.sid)

    write_audit_log(
        'WINRM_SESSION_START',
        operator=username,
        source_ip=request.remote_addr or 'unknown',
        target_asset=f"{asset.hostname or asset.ip}({asset.ip}:{asset.ssh_port})",
        result='success',
        operation_detail=f"WinRM会话{session_id}开始 - Windows资产",
    )


@socketio.on('dangerous_command_signature')
def handle_dangerous_command_signature(data):
    nonce = data.get('nonce')
    future = _pending_signatures.get(nonce)
    if future:
        future.set_result(data)


@socketio.on('winrm_input')
def handle_winrm_input(data):
    """记录用户在 PowerShell 终端中的按键输入到录像文件"""
    session_id = data.get('session_id')
    input_data = data.get('input', '')

    conn_info = active_connections.get(session_id)
    if not conn_info:
        return

    try:
        _write_recording_output(conn_info, input_data, '')
    except Exception as e:
        logger.error('[WINRM WS] Input recording error: %s', str(e))


@socketio.on('command')
def handle_command(data):
    session_id = data.get('session_id')
    cmd = data.get('cmd', '').strip()

    conn_info = active_connections.get(session_id)
    if not conn_info:
        emit('error', {'message': 'Session not found'}, room=request.sid)
        return

    conn_info['last_activity'] = time.time()
    if conn_info.get('idle_timer'):
        conn_info['idle_timer'].cancel()
    idle_timer = threading.Timer(1800.0, _idle_timeout, args=[session_id])
    idle_timer.daemon = True
    idle_timer.start()
    conn_info['idle_timer'] = idle_timer

    # 记录输入命令到录像（兜底：即使前端 keystroke 事件丢失，完整命令也会被捕获）
    _write_recording_output(conn_info, cmd + '\r\n', '')

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
            emit('output', {
                'stdout': '',
                'stderr': '# PAM SECURITY: 签名超时，命令已被拒绝执行',
                'exit_code': 1
            }, room=request.sid)
            _write_recording_output(conn_info, '', '# PAM SECURITY: 签名超时，命令已被拒绝执行')
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
            emit('output', {
                'stdout': '',
                'stderr': '# PAM SECURITY: 用户取消签名，命令已被拒绝执行',
                'exit_code': 1
            }, room=request.sid)
            _write_recording_output(conn_info, '', '# PAM SECURITY: 用户取消签名，命令已被拒绝执行')
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
            emit('output', {
                'stdout': '',
                'stderr': '# PAM SECURITY: 用户未配置SM2公钥，无法验签',
                'exit_code': 1
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

        challenge_str = json.dumps(challenge_data, separators=(',', ':'))
        valid = CryptoService.sm2_verify_with_public_key(challenge_str, signature, user.sm2_public_key)
        if not valid:
            emit('output', {
                'stdout': '',
                'stderr': '# PAM SECURITY: 签名验证失败，命令已被拒绝执行',
                'exit_code': 1
            }, room=request.sid)
            _write_recording_output(conn_info, '', '# PAM SECURITY: 签名验证失败，命令已被拒绝执行')
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

    command_result = {}
    command_done = threading.Event()
    command_timeout = 60

    def _run_command():
        try:
            protocol = conn_info['protocol']
            shell_id = conn_info['shell_id']
            command_id = protocol.run_command(shell_id, cmd)
            stdout, stderr, exit_code = protocol.get_command_output(shell_id, command_id)
            command_result['stdout'] = stdout.decode('utf-8', errors='ignore') if stdout else ''
            command_result['stderr'] = stderr.decode('utf-8', errors='ignore') if stderr else ''
            command_result['exit_code'] = exit_code
            command_result['command_id'] = command_id
        except Exception as e:
            command_result['error'] = str(e)
        finally:
            command_done.set()

    t = threading.Thread(target=_run_command, daemon=True)
    t.start()
    timed_out = not command_done.wait(timeout=command_timeout)

    if timed_out:
        try:
            protocol = conn_info['protocol']
            shell_id = conn_info['shell_id']
            kill_cmd = f"taskkill /F /T /PID $(Get-Process -Id (Get-WmiObject Win32_Process -Filter \"CommandLine like '%{cmd[:20]}%'\").ProcessId).Id 2>$null"
            protocol.run_command(shell_id, kill_cmd)
        except:
            pass
        emit('output', {
            'stdout': '',
            'stderr': '# PAM: 命令执行超时（60秒），已被系统强制中止',
            'exit_code': 1
        }, room=request.sid)
        _write_recording_output(conn_info, '', '# PAM: 命令执行超时（60秒），已被系统强制中止')
        write_audit_log(
            'WINRM_COMMAND_TIMEOUT',
            operator=conn_info.get('username', 'unknown'),
            source_ip=request.remote_addr or 'unknown',
            target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
            operation_detail=f'命令执行超时(60s): {cmd}',
            result='timeout'
        )
        _reopen_shell(session_id, conn_info)
        return

    if 'error' in command_result:
        logger.error('[WINRM WS] Command execution failed: %s', command_result['error'])
        emit('output', {
            'stdout': '',
            'stderr': f'# Command execution error: {command_result["error"]}',
            'exit_code': 1
        }, room=request.sid)
        write_audit_log(
            'WINRM_COMMAND_EXEC',
            operator=conn_info.get('username', 'unknown'),
            source_ip=request.remote_addr or 'unknown',
            target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
            operation_detail=f'执行命令失败: {cmd}',
            result='error'
        )
        return

    try:
        protocol = conn_info['protocol']
        shell_id = conn_info['shell_id']
        protocol.cleanup_command(shell_id, command_result['command_id'])
    except:
        pass

    stdout = command_result.get('stdout', '')
    stderr = command_result.get('stderr', '')
    exit_code = command_result.get('exit_code', 0)

    emit('output', {
        'stdout': stdout,
        'stderr': stderr,
        'exit_code': exit_code
    }, room=request.sid)

    _write_recording_output(conn_info, stdout, stderr)

    log_result = 'success' if exit_code == 0 else 'error'
    if not blocked:
        write_audit_log(
            'WINRM_COMMAND_EXEC',
            operator=conn_info.get('username', 'unknown'),
            source_ip=request.remote_addr or 'unknown',
            target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
            operation_detail=f'执行命令: {cmd}',
            result=log_result
        )


def _write_recording_output(conn_info, stdout, stderr):
    try:
        initial_timestamp = conn_info.get('initial_timestamp', time.time())
        time_diff = round(time.time() - initial_timestamp, 6)
        combined = stdout + stderr
        if combined:
            output_data = [time_diff, combined]
            line = json.dumps(output_data, separators=(',', ':'), ensure_ascii=False) + '\n'
            conn_info['recording_file'].write(line)
            conn_info['recording_file'].flush()
    except Exception as e:
        logger.error('[WINRM WS] Recording write error: %s', str(e))


def _reopen_shell(session_id, conn_info):
    try:
        old_shell_id = conn_info.get('shell_id')
        if old_shell_id and conn_info.get('protocol'):
            try:
                conn_info['protocol'].close_shell(old_shell_id)
            except:
                pass
        new_shell_id = conn_info['protocol'].open_shell()
        conn_info['shell_id'] = new_shell_id
        auto_cmd = "$ConfirmPreference = 'None'; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8"
        result = conn_info['protocol'].run_command(new_shell_id, auto_cmd)
        conn_info['protocol'].cleanup_command(new_shell_id, result)
        current_app.logger.info('[WINRM WS] Shell reopened for session %s due to timeout', session_id)
    except Exception as e:
        current_app.logger.error('[WINRM WS] Failed to reopen shell for session %s: %s', session_id, str(e))


def _idle_timeout(session_id):
    conn_info = active_connections.get(session_id)
    if not conn_info:
        return
    elapsed = time.time() - conn_info.get('last_activity', time.time())
    if elapsed >= 1800:
        current_app.logger.info('[WINRM WS] Idle timeout for session %s', session_id)
        write_audit_log(
            'WINRM_SESSION_TIMEOUT',
            operator=conn_info.get('username', 'unknown'),
            source_ip='unknown',
            target_asset=f"{conn_info.get('asset_ip')}:{conn_info.get('asset_port')}",
            operation_detail='WinRM会话空闲超时(30分钟)',
            result='timeout'
        )
        _cleanup_connection(session_id)