from flask import Blueprint, jsonify
from app.models import SessionRecord, Asset
from app.utils.auth import token_required, role_required
from app.services.crypto_service import CryptoService
from app.utils.logger import get_logger
import os
import struct

logger = get_logger('app.api.session')
session_bp = Blueprint('session', __name__, url_prefix='/api/sessions')

def _read_encrypted_recording(filepath):
    with open(filepath, 'rb') as f:
        dek_len_bytes = f.read(4)
        if len(dek_len_bytes) < 4:
            raise ValueError('ENCRYPTED_FILE_FORMAT_ERROR')
        dek_len = struct.unpack('>I', dek_len_bytes)[0]
        encrypted_dek = f.read(dek_len)
        if len(encrypted_dek) < dek_len:
            raise ValueError('ENCRYPTED_FILE_FORMAT_ERROR')
        iv = f.read(16)
        if len(iv) < 16:
            raise ValueError('ENCRYPTED_FILE_FORMAT_ERROR')
        ciphertext = f.read()
        if not ciphertext:
            raise ValueError('ENCRYPTED_FILE_FORMAT_ERROR')
    dek = CryptoService.decrypt_dek_with_master_key(encrypted_dek)
    if dek is None:
        raise ValueError('DEK_DECRYPT_FAILED')
    try:
        plaintext = CryptoService.sm4_cbc_decrypt_bytes(ciphertext, dek, iv)
        content = plaintext.decode('utf-8')
        if '\r\n' in content:
            content = content.replace('\r\n', '\n')
        return content
    except Exception:
        raise ValueError('RECORDING_DECRYPT_FAILED')

@session_bp.route('', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_sessions():
    sessions = SessionRecord.query.order_by(SessionRecord.start_time.desc()).all()
    result = []
    for session in sessions:
        asset_ip = session.asset.ip if session.asset else 'Unknown'
        asset_port = session.asset.ssh_port if session.asset else 22
        target_asset = f"{asset_ip}:{asset_port}"
        if session.end_time:
            duration_seconds = int((session.end_time - session.start_time).total_seconds())
            hours = duration_seconds // 3600
            minutes = (duration_seconds % 3600) // 60
            seconds = duration_seconds % 60
            if hours > 0:
                duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                duration = f"{minutes:02d}:{seconds:02d}"
        else:
            duration = "进行中"
        operator = session.operator_name if session.operator_name else '未知操作人'
        result.append({
            'id': session.id,
            'asset_id': session.asset_id,
            'asset_name': session.asset.hostname if session.asset else 'Unknown',
            'target_asset': target_asset,
            'user_id': session.user_id,
            'session_id': session.session_id,
            'start_time': session.start_time.isoformat(),
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'duration': duration,
            'operator': operator
        })
    return jsonify({
        'code': 200,
        'message': 'Success',
        'data': result
    })

@session_bp.route('/<int:session_id>/info', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_session_info(session_id):
    session = SessionRecord.query.get(session_id)
    if not session:
        return jsonify({
            'code': 404,
            'message': 'Session not found'
        }), 404
    asset_ip = session.asset.ip if session.asset else 'Unknown'
    asset_port = session.asset.ssh_port if session.asset else 22
    target_asset = f"{asset_ip}:{asset_port}"
    operator = session.operator_name if session.operator_name else '未知操作人'
    return jsonify({
        'code': 200,
        'message': 'Success',
        'data': {
            'id': session.id,
            'asset_id': session.asset_id,
            'asset_name': session.asset.hostname if session.asset else 'Unknown',
            'target_asset': target_asset,
            'user_id': session.user_id,
            'operator': operator,
            'session_id': session.session_id,
            'start_time': session.start_time.isoformat(),
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'recording_path': session.recording_path
        }
    })

@session_bp.route('/<int:session_id>/playback', methods=['GET'])
@token_required
@role_required('admin', 'auditor')
def get_session_playback(session_id):
    session = SessionRecord.query.get(session_id)
    if not session:
        return jsonify({
            'code': 404,
            'message': 'Session not found'
        }), 404
    if not os.path.exists(session.recording_path):
        return jsonify({
            'code': 404,
            'message': 'Recording file not found'
        }), 404
    filepath = session.recording_path
    try:
        if filepath.endswith('.cast.enc'):
            content = _read_encrypted_recording(filepath)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        return jsonify({
            'code': 200,
            'message': 'Success',
            'data': {
                'content': content
            }
        })
    except ValueError as e:
        err_msg = str(e)
        if err_msg == 'ENCRYPTED_FILE_FORMAT_ERROR':
            logger.error('[PLAYBACK] 录像文件格式异常: session_id=%s, path=%s', session_id, filepath)
            return jsonify({'code': 500, 'message': '录像文件格式异常'}), 500
        elif err_msg == 'DEK_DECRYPT_FAILED':
            logger.error('[PLAYBACK] 录像加密密钥无法解密: session_id=%s', session_id)
            return jsonify({'code': 500, 'message': '录像加密密钥无法解密，请联系管理员'}), 500
        elif err_msg == 'RECORDING_DECRYPT_FAILED':
            logger.error('[PLAYBACK] 录像文件已损坏: session_id=%s, path=%s', session_id, filepath)
            return jsonify({'code': 500, 'message': '录像文件已损坏，无法回放'}), 500
        logger.error('[PLAYBACK] 录像读取异常: session_id=%s, %s', session_id, err_msg)
        return jsonify({
            'code': 500,
            'message': '读取录像文件失败'
        }), 500
    except Exception as e:
        logger.error('[PLAYBACK] 录像读取异常: session_id=%s, %s', session_id, str(e))
        return jsonify({
            'code': 500,
            'message': '读取录像文件失败'
        }), 500