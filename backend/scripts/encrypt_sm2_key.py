"""
SM2 私钥加密工具
使用 PBKDF2 + AES-GCM 加密明文 SM2 私钥
输出格式：salt_b64:nonce_b64:ciphertext_b64

配合 crypto_service.py 中的 decrypt_private_key() 使用。

使用方法：
    cd backend
    python scripts/encrypt_sm2_key.py
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_private_key(plaintext: str, password: str) -> str:
    """
    加密SM2私钥
    输出格式: salt_b64:nonce_b64:ciphertext_b64
    与 decrypt_private_key 中的解密逻辑完全对应
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    salt_b64 = base64.b64encode(salt).decode()
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    return f"{salt_b64}:{nonce_b64}:{ciphertext_b64}"


if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from dotenv import load_dotenv
    load_dotenv()

    plain_key = os.getenv('SM2_PRIVATE_KEY')
    if not plain_key:
        print("[ERROR] SM2_PRIVATE_KEY not found in .env")
        sys.exit(1)

    if len(sys.argv) >= 2:
        password = sys.argv[1]
    else:
        import getpass
        password = getpass.getpass("Enter encryption password: ").strip()

    if not password:
        print("[ERROR] Password cannot be empty")
        sys.exit(1)

    encrypted = encrypt_private_key(plain_key, password)
    print("=" * 60)
    print("SM2 private key encrypted successfully!")
    print("=" * 60)
    print()
    print("Add/update these lines in .env:")
    print()
    print(f"SM2_PRIVATE_KEY_ENCRYPTED=true")
    print(f"SM2_PRIVATE_KEY_ENCRYPTED_DATA={encrypted}")
    print()
    print("Then start with:")
    print("  cd backend")
    print('  powershell -ExecutionPolicy Bypass -File start.ps1 -Password "mypam2026!"')
    print()
