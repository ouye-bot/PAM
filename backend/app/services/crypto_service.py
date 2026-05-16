import os
import re
import secrets
import base64
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl.sm3 import sm3_hash
from dotenv import load_dotenv
from app.utils.logger import get_logger

logger = get_logger('app.services.crypto_service')


def secure_random_hex(length):
    """使用 os.urandom 生成密码学安全的随机十六进制字符串。
    绝不使用 gmssl.func.random_hex（它基于 Python random 模块，不安全）。"""
    return secrets.token_hex(length // 2)


# Monkey-patch gmssl 的不安全随机数生成器
# gmssl.func.random_hex 使用 Python random.choice()（Mersenne Twister），
# 不是密码学安全的。替换为基于 secrets 模块的安全版本。
import gmssl.func as _gmssl_func
_gmssl_func.random_hex = lambda x: secrets.token_hex(x // 2)

load_dotenv()

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYRING_SERVICE = "PAM"
KEYRING_USERNAME = "master_key"

def _get_keyring():
    try:
        import keyring
        backend = os.getenv('KEYRING_BACKEND')
        if backend:
            import keyrings.cryptfile
            keyring.set_keyring(keyrings.cryptfile.CryptFileKeyring())
        return keyring
    except ImportError:
        return None
    except Exception as e:
        logger.info("[KEYRING] Warning: Failed to initialize keyring: %s", e)
        return None

def get_master_key():
    """
    获取主密钥
    优先级：系统密钥链 > 环境变量 MASTER_KEY
    """
    master_key = None
    keyring_source = None

    keyring = _get_keyring()
    if keyring:
        try:
            stored_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if stored_key:
                master_key = stored_key
                keyring_source = "keyring"
                logger.info("[CRYPTO] Master key loaded from system keyring")
        except Exception as e:
            logger.info("[CRYPTO] Warning: Failed to read from keyring: %s", e)

    if not master_key:
        master_key = os.getenv('MASTER_KEY')
        if master_key:
            keyring_source = "env"
            logger.info("[CRYPTO] Master key loaded from environment variable")

    if not master_key:
        raise RuntimeError(
            "环境变量 MASTER_KEY 未配置，系统无法启动。\n"
            "请设置环境变量 MASTER_KEY（32字节长度的密钥），例如：\n"
            "  python -c \"import secrets; print(secrets.token_hex(16))\"\n"
            "并将输出的32位十六进制字符串设置为 MASTER_KEY 的值。"
        )

    if len(master_key) != 32:
        raise RuntimeError(
            f"MASTER_KEY 长度必须为32字符，当前为 {len(master_key)} 字符"
        )

    if not re.match(r'^[0-9a-fA-F]{32}$', master_key):
        safe_sample = master_key[:4] + '...' + master_key[-4:]
        raise RuntimeError(
            f"MASTER_KEY 格式错误：必须为32位十六进制字符串（0-9, a-f），"
            f"当前值 '{safe_sample}' 包含非法字符"
        )

    return master_key.encode()

def store_master_key_to_keyring(master_key):
    keyring = _get_keyring()
    if not keyring:
        logger.info("[CRYPTO] Warning: keyring not available, skipping keyring storage")
        return False

    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, master_key)
        logger.info("[CRYPTO] Master key stored to system keyring")
        return True
    except Exception as e:
        logger.info("[CRYPTO] Warning: Failed to store key to keyring: %s", e)
        return False

class CryptoService:
    @staticmethod
    def get_master_key():
        """获取主密钥，从密钥链或环境变量读取"""
        return get_master_key()

    @staticmethod
    def get_or_create_work_key():
        """获取或创建工作密钥（优先使用 rotating 状态的新密钥）"""
        from .. import db
        from ..models import KeyVersion

        # 优先使用 rotating 状态的新密钥（平滑轮换期间新加密用新密钥）
        active_key = (KeyVersion.query.filter_by(status='rotating').first()
                      or KeyVersion.query.filter_by(status='active').first())
        if active_key:
            master_key = CryptoService.get_master_key()
            encrypted_key = active_key.encrypted_key
            work_key = CryptoService._decrypt_with_master_key(encrypted_key, master_key)
            if work_key is None:
                raise RuntimeError("工作密钥解密失败：主密钥可能已更换或数据损坏")
            return work_key, active_key.id

        import secrets
        work_key = secrets.token_bytes(16)
        master_key = CryptoService.get_master_key()
        encrypted_work_key = CryptoService._encrypt_with_master_key(work_key, master_key)

        new_key = KeyVersion(
            encrypted_key=encrypted_work_key,
            status='active'
        )
        db.session.add(new_key)
        db.session.commit()

        return work_key, new_key.id

    @staticmethod
    def sm4_encrypt(plaintext):
        """使用工作密钥加密明文（SM4-CBC加密 + SM3-HMAC认证）"""
        work_key, key_version = CryptoService.get_or_create_work_key()
        sm4 = CryptSM4()
        sm4.set_key(work_key, SM4_ENCRYPT)
        iv = os.urandom(16)
        ciphertext = sm4.crypt_cbc(iv, plaintext.encode())
        payload = iv + ciphertext
        hmac_hex = CryptoService.sm3_hash((work_key + payload).hex())
        hmac_bytes = bytes.fromhex(hmac_hex)
        result = base64.b64encode(payload + hmac_bytes).decode()
        return result, key_version

    @staticmethod
    def sm4_decrypt(ciphertext, key_version_id):
        """使用指定版本的工作密钥解密，失败返回 None"""
        from ..models import KeyVersion

        key_version = KeyVersion.query.get(key_version_id)
        if not key_version:
            logger.error("[DECRYPT] 密钥版本不存在: key_version_id=%s", key_version_id)
            return None

        if not ciphertext:
            logger.error("[DECRYPT] encrypted_password 为空: key_version_id=%s", key_version_id)
            return None

        try:
            master_key = CryptoService.get_master_key()
        except RuntimeError as e:
            logger.error("[DECRYPT] 主密钥获取失败: %s", e)
            return None

        work_key = CryptoService._decrypt_with_master_key(key_version.encrypted_key, master_key)
        if work_key is None:
            logger.critical("[DECRYPT] 工作密钥解密失败: key_version_id=%s, 主密钥可能已更换", key_version_id)
            return None

        try:
            data = base64.b64decode(ciphertext.encode())
        except (ValueError, TypeError) as e:
            logger.error("[DECRYPT] Base64 解码失败: key_version_id=%s, %s", key_version_id, e)
            return None

        # SM3-HMAC 认证：验证密文完整性（encrypt-then-MAC）
        if len(data) >= 48:
            payload = data[:-32]
            stored_hmac = data[-32:].hex()
            expected_hmac = CryptoService.sm3_hash((work_key + payload).hex())
            if stored_hmac != expected_hmac:
                logger.error("[DECRYPT] SM3-HMAC 认证失败: key_version_id=%s, 密文可能被篡改", key_version_id)
                return None
            data = payload

        try:
            iv = data[:16]
            actual_ciphertext = data[16:]
        except IndexError as e:
            logger.error("[DECRYPT] 密文数据长度不足: key_version_id=%s, len=%d, %s",
                         key_version_id, len(data), e)
            return None

        try:
            sm4 = CryptSM4()
            sm4.set_key(work_key, SM4_DECRYPT)
            plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
            return plaintext.decode()
        except UnicodeDecodeError as e:
            logger.error("[DECRYPT] 解密结果UTF-8解码失败: key_version_id=%s, %s", key_version_id, e)
            return None
        except Exception as e:
            # 兼容模式：早期版本(P4之前)使用全零IV加密，密文中不包含IV前缀。
            # 当标准解密失败时，尝试用零IV解密原始数据以兼容旧格式。
            # 注意：此回退会绕过IV的语义安全性——仅用于向后兼容，新加密数据一律使用随机IV+前缀格式。
            logger.warning("[DECRYPT] 标准解密失败，尝试零IV兼容模式: key_version_id=%s, err=%s", key_version_id, e)
            try:
                iv = b'\x00' * 16
                actual_ciphertext = data
                sm4 = CryptSM4()
                sm4.set_key(work_key, SM4_DECRYPT)
                plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
                return plaintext.decode()
            except UnicodeDecodeError as e2:
                logger.error("[DECRYPT] 兼容模式UTF-8解码失败: key_version_id=%s, %s", key_version_id, e2)
                return None
            except Exception as e2:
                logger.error("[DECRYPT] 业务密码解密失败(主密钥可能已更换): key_version_id=%s, %s",
                             key_version_id, e2)
                return None

    @staticmethod
    def _encrypt_with_master_key(data, master_key):
        """使用主密钥加密数据"""
        sm4 = CryptSM4()
        sm4.set_key(master_key, SM4_ENCRYPT)
        iv = os.urandom(16)
        ciphertext = sm4.crypt_cbc(iv, data)
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def _decrypt_with_master_key(encrypted_data, master_key):
        """使用主密钥解密数据，失败返回 None"""
        try:
            data = base64.b64decode(encrypted_data.encode())
        except (ValueError, TypeError) as e:
            logger.error("[DECRYPT] 主密钥解密 - Base64解码失败: %s", e)
            return None

        try:
            iv = data[:16]
            ciphertext = data[16:]
        except IndexError as e:
            logger.error("[DECRYPT] 主密钥解密 - 数据长度不足: len=%d, %s", len(data), e)
            return None

        try:
            sm4 = CryptSM4()
            sm4.set_key(master_key, SM4_DECRYPT)
            plaintext = sm4.crypt_cbc(iv, ciphertext)
            return plaintext
        except Exception as e:
            logger.error("[DECRYPT] 主密钥解密 - SM4解密失败(密钥可能不匹配): %s", e)
            return None

    @staticmethod
    def sm3_hash(data):
        """使用SM3计算哈希值"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        data_list = list(data)
        hash_value = sm3_hash(data_list)
        return hash_value

    @staticmethod
    def generate_work_key():
        """生成16字节的工作密钥"""
        import secrets
        return secrets.token_bytes(16)

    @staticmethod
    def sm4_cbc_encrypt_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
        """使用SM4-CBC模式加密bytes数据，返回(iv, ciphertext)"""
        sm4 = CryptSM4()
        sm4.set_key(key, SM4_ENCRYPT)
        iv = os.urandom(16)
        ciphertext = sm4.crypt_cbc(iv, plaintext)
        return iv, ciphertext

    @staticmethod
    def sm4_cbc_decrypt_bytes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """使用SM4-CBC模式解密bytes数据，返回明文"""
        sm4 = CryptSM4()
        sm4.set_key(key, SM4_DECRYPT)
        plaintext = sm4.crypt_cbc(iv, ciphertext)
        return plaintext

    @staticmethod
    def encrypt_dek_with_master_key(dek: bytes) -> bytes:
        """用主密钥加密DEK，返回原始密文字节"""
        master_key = CryptoService.get_master_key()
        encrypted_b64 = CryptoService._encrypt_with_master_key(dek, master_key)
        return base64.b64decode(encrypted_b64)

    @staticmethod
    def decrypt_dek_with_master_key(encrypted_dek: bytes) -> bytes:
        """用主密钥解密DEK，返回DEK原始字节，失败返回None"""
        master_key = CryptoService.get_master_key()
        encrypted_b64 = base64.b64encode(encrypted_dek).decode()
        dek = CryptoService._decrypt_with_master_key(encrypted_b64, master_key)
        if dek is None:
            logger.error("[DECRYPT] DEK解密失败: 主密钥可能已轮换")
        return dek

    @staticmethod
    def encrypt_work_key(work_key):
        """用主密钥加密工作密钥"""
        master_key = CryptoService.get_master_key()
        return CryptoService._encrypt_with_master_key(work_key, master_key)

    @staticmethod
    def decrypt_work_key(encrypted_key):
        """用主密钥解密工作密钥，失败返回 None"""
        try:
            master_key = CryptoService.get_master_key()
        except RuntimeError as e:
            logger.error("[DECRYPT] decrypt_work_key - 主密钥获取失败: %s", e)
            return None
        return CryptoService._decrypt_with_master_key(encrypted_key, master_key)

    @staticmethod
    def encrypt_with_work_key(password, work_key):
        """用工作密钥加密密码"""
        sm4 = CryptSM4()
        sm4.set_key(work_key, SM4_ENCRYPT)
        iv = os.urandom(16)
        ciphertext = sm4.crypt_cbc(iv, password.encode())
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_with_work_key(encrypted_password, work_key):
        """用工作密钥解密密码，失败返回 None"""
        try:
            data = base64.b64decode(encrypted_password.encode())
        except (ValueError, TypeError) as e:
            logger.error("[DECRYPT] decrypt_with_work_key - Base64解码失败: %s", e)
            return None

        try:
            iv = data[:16]
            actual_ciphertext = data[16:]
        except IndexError as e:
            logger.error("[DECRYPT] decrypt_with_work_key - 数据长度不足: len=%d, %s", len(data), e)
            return None

        try:
            sm4 = CryptSM4()
            sm4.set_key(work_key, SM4_DECRYPT)
            plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
            return plaintext.decode()
        except UnicodeDecodeError as e:
            logger.error("[DECRYPT] decrypt_with_work_key - UTF-8解码失败: %s", e)
            return None
        except Exception as e:
            try:
                iv = b'\x00' * 16
                actual_ciphertext = data
                sm4 = CryptSM4()
                sm4.set_key(work_key, SM4_DECRYPT)
                plaintext = sm4.crypt_cbc(iv, actual_ciphertext)
                return plaintext.decode()
            except UnicodeDecodeError as e2:
                logger.error("[DECRYPT] decrypt_with_work_key - 兼容模式UTF-8解码失败: %s", e2)
                return None
            except Exception as e2:
                logger.error("[DECRYPT] decrypt_with_work_key - 解密失败(密文可能损坏): %s", e2)
                return None

    @staticmethod
    def sm2_verify_with_public_key(data: str, signature_b64: str, public_key_b64: str) -> bool:
        """用指定的公钥(Base64)验签SM2签名(Base64)"""
        from gmssl import sm2
        import base64 as b64

        try:
            pub_bytes = b64.b64decode(public_key_b64)
            pub_hex = pub_bytes.hex()
            sig_bytes = b64.b64decode(signature_b64)
            sig_hex = sig_bytes.hex()
            sm2_crypt = sm2.CryptSM2(private_key="", public_key=pub_hex)
            return sm2_crypt.verify(sig_hex, data.encode())
        except Exception as e:
            logger.warning("[SM2_VERIFY] 验签异常: %s", e)
            return False

    @staticmethod
    def re_encrypt_all_credentials(old_key_id, new_key_id, old_work_key, new_work_key):
        """
        Synchronously re-encrypt ALL credential data from old_key to new_key.
        Returns: (migrated: int, failed: int, errors: list)
        On partial failure, committed per-batch — old key stays active.
        """
        from app import db
        from app.models import Credential
        import json

        errors = []
        migrated = 0
        failed = 0
        batch_size = 50

        total = Credential.query.count()
        offset = 0
        while offset < total:
            batch = Credential.query.order_by(Credential.id).offset(offset).limit(batch_size).all()
            if not batch:
                break
            for cred in batch:
                try:
                    # Re-encrypt encrypted_password
                    if cred.key_version == old_key_id:
                        password = CryptoService.decrypt_with_work_key(cred.encrypted_password, old_work_key)
                        if password is None:
                            raise ValueError(f"Decrypt failed for cred {cred.id}")
                        cred.encrypted_password = CryptoService.encrypt_with_work_key(password, new_work_key)
                        cred.key_version = new_key_id

                    # Re-encrypt pending_password
                    if cred.pending_password and cred.pending_key_version == old_key_id:
                        pending = CryptoService.decrypt_with_work_key(cred.pending_password, old_work_key)
                        if pending is not None:
                            cred.pending_password = CryptoService.encrypt_with_work_key(pending, new_work_key)
                            cred.pending_key_version = new_key_id

                    # Re-encrypt previous_passwords JSON
                    if cred.previous_passwords and cred.previous_passwords != '[]':
                        try:
                            prev_list = json.loads(cred.previous_passwords)
                            re_encrypted = False
                            for entry in prev_list:
                                if entry.get('key_version') == old_key_id:
                                    old_pwd = CryptoService.decrypt_with_work_key(entry['encrypted_password'], old_work_key)
                                    if old_pwd is not None:
                                        entry['encrypted_password'] = CryptoService.encrypt_with_work_key(old_pwd, new_work_key)
                                        entry['key_version'] = new_key_id
                                        re_encrypted = True
                            if re_encrypted:
                                cred.previous_passwords = json.dumps(prev_list, ensure_ascii=False)
                        except (json.JSONDecodeError, KeyError):
                            pass

                    migrated += 1
                except Exception as e:
                    failed += 1
                    errors.append(f"cred_id={cred.id}: {str(e)}")

            db.session.commit()
            offset += batch_size

        return migrated, failed, errors

# SM2签名相关函数
def decrypt_private_key(encrypted_data: str, password: str) -> str:
    try:
        salt_b64, nonce_b64, ciphertext_b64 = encrypted_data.split(':')
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        raise ValueError(f"SM2私钥解密失败: {str(e)}")

def get_sm2_private_key():
    if os.getenv('SM2_PRIVATE_KEY_ENCRYPTED', 'false').lower() == 'true':
        encrypted_data = os.getenv('SM2_PRIVATE_KEY_ENCRYPTED_DATA')
        password = os.getenv('SM2_PRIVATE_KEY_PASSWORD')
        if not encrypted_data:
            raise ValueError("SM2私钥已加密，但未找到加密数据，请检查环境变量")
        if not password:
            raise ValueError("SM2私钥已加密，请设置SM2_PRIVATE_KEY_PASSWORD环境变量")
        return decrypt_private_key(encrypted_data, password)

    plain_key = os.getenv('SM2_PRIVATE_KEY')
    if plain_key:
        return plain_key

    raise ValueError("未找到SM2私钥")

def _calculate_sm2_public_key(private_key):
    from gmssl import sm2
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")
    private_key_int = int(private_key, 16)
    g = sm2_crypt.ecc_table['g']
    public_key = sm2_crypt._kg(private_key_int, g)
    return public_key

def get_sm2_public_key():
    private_key = get_sm2_private_key()
    if not private_key:
        return None
    return _calculate_sm2_public_key(private_key)

def _sm2_deterministic_k(private_key_hex: str, message_hash_hex: str, n_hex: str) -> str:
    """
    Derive a deterministic k value for SM2 signing per RFC 6979 concept.
    Uses iterative SM3 over (private_key || message_hash || counter) as the entropy source.
    Loops until k is in the valid range [1, n-1].
    """
    from gmssl.sm3 import sm3_hash as _sm3
    n = int(n_hex, 16)
    seed = (private_key_hex + message_hash_hex).encode()
    extra = 0
    while True:
        k_input = seed + extra.to_bytes(4, 'big')
        k_hex = _sm3(list(k_input))
        k = int(k_hex, 16) % n
        if 1 <= k <= n - 1:
            return hex(k)[2:].zfill(64)
        extra += 1


def sm2_sign(data: str) -> str:
    from gmssl import sm2

    private_key = get_sm2_private_key()
    if not private_key:
        raise ValueError("SM2 私钥未配置")

    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")

    # Compute SM3 hash of the message
    msg_hash = CryptoService.sm3_hash(data)

    # Derive deterministic k from private key + message hash
    n_hex = sm2_crypt.ecc_table['n']
    deterministic_k = _sm2_deterministic_k(private_key, msg_hash, n_hex)

    signature_hex = sm2_crypt.sign(data.encode(), deterministic_k)
    return base64.b64encode(signature_hex.encode()).decode()

def sm2_verify(data: str, signature: str) -> bool:
    from gmssl import sm2

    public_key = get_sm2_public_key()
    if not public_key:
        return False

    try:
        sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)
        sign_bytes = base64.b64decode(signature)
        signature_hex = sign_bytes.decode() if isinstance(sign_bytes, bytes) else sign_bytes
        return sm2_crypt.verify(signature_hex, data.encode())
    except Exception:
        return False


