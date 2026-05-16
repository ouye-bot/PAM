import os
import secrets
from dotenv import load_dotenv, dotenv_values

load_dotenv()

KEYRING_SERVICE = "PAM"
KEYRING_USERNAME = "master_key"

def _get_keyring():
    """
    获取keyring后端，支持多平台配置
    """
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
        print(f"[KEYRING] Warning: Failed to initialize keyring: {e}")
        return None

def generate_master_key():
    """生成32字节的主密钥"""
    return secrets.token_hex(16)

def store_to_keyring(master_key):
    """将主密钥存储到系统密钥链"""
    keyring = _get_keyring()
    if not keyring:
        print("[INIT] Warning: keyring not available, skipping keyring storage")
        return False

    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, master_key)
        print("[INIT] Master key stored to system keyring")
        return True
    except Exception as e:
        print(f"[INIT] Warning: Failed to store key to keyring: {e}")
        return False

def update_env_file(key, value, comment=None):
    """更新.env文件"""
    env_path = '.env'
    env_vars = dotenv_values(env_path)
    env_vars[key] = value

    with open(env_path, 'w') as f:
        for k, v in env_vars.items():
            if comment and k == key:
                f.write(f"# {comment}\n")
            f.write(f"{k}={v}\n")

def init_master_key():
    """初始化主密钥"""
    existing_key = os.getenv('MASTER_KEY')
    if existing_key:
        print("[INIT] Master key already exists in environment variable")
        print("[INIT] Storing to keyring for enhanced security...")

        keyring = _get_keyring()
        if keyring:
            try:
                existing_stored = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
                if existing_stored == existing_key:
                    print("[INIT] Key already in keyring, skipping")
                else:
                    store_to_keyring(existing_key)
            except Exception as e:
                print(f"[INIT] Warning: Failed to check keyring: {e}")
                store_to_keyring(existing_key)
        else:
            store_to_keyring(existing_key)
        return

    keyring = _get_keyring()
    if keyring:
        try:
            stored_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            if stored_key:
                print("[INIT] Found existing master key in keyring")
                if len(stored_key) == 32:
                    update_env_file('MASTER_KEY', stored_key, "Master key (backup, primary stored in system keyring)")
                    print("[INIT] Master key restored from keyring to .env")
                    return
        except Exception as e:
            print(f"[INIT] Warning: Failed to read from keyring: {e}")

    master_key = generate_master_key()
    print(f"[INIT] Generated master key: {master_key}")

    update_env_file('MASTER_KEY', master_key, "Master key (backup, primary stored in system keyring)")
    print("[INIT] Master key written to .env file")

    store_to_keyring(master_key)

if __name__ == '__main__':
    init_master_key()
    print("[INIT] Master key initialization completed.")
