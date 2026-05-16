import os
import struct
import json
from app import db
from app.services.crypto_service import CryptoService
from app.utils.logger import get_logger

logger = get_logger('app.services.recording_service')

RECORDINGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'recordings')


def ensure_recordings_dir():
    if not os.path.exists(RECORDINGS_DIR):
        os.makedirs(RECORDINGS_DIR)
    return RECORDINGS_DIR


def start_recording(asset_id, user_id, session_id):
    """Create a new recording file and return (file_handle, file_path)."""
    ensure_recordings_dir()
    filename = f"{asset_id}_{user_id}_{session_id}.cast"
    filepath = os.path.join(RECORDINGS_DIR, filename)
    fh = open(filepath, 'w', encoding='utf-8')
    return fh, filepath


def write_recording_header(fh, width, height, start_timestamp):
    """Write asciicast v2 header."""
    header = {"version": 2, "width": width, "height": height, "timestamp": int(start_timestamp)}
    header_line = json.dumps(header, ensure_ascii=False) + "\n"
    fh.write(header_line)
    fh.flush()


def append_recording_frame(fh, data, timestamp):
    """Append a single asciicast frame [timestamp, data]."""
    line = json.dumps([timestamp, data], ensure_ascii=False) + "\n"
    fh.write(line)
    fh.flush()


def finish_recording(session_record):
    """Encrypt the plaintext .cast file with SM4-CBC + DEK, save as .cast.enc, delete plaintext."""
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
    logger.info("[RECORDING] Encrypted recording saved: %s", enc_path)


def cleanup_recording(file_handle, session_record):
    """Close file handle and encrypt recording."""
    if file_handle:
        try:
            file_handle.close()
        except Exception:
            pass
    finish_recording(session_record)
