#!/usr/bin/env python3
"""SM2密钥初始化脚本 - 支持加密存储"""
import os
import base64
import secrets
import getpass
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def encrypt_private_key(private_key: str, password: str) -> str:
    """
    使用PBKDF2+AES-256-GCM加密私钥
    返回格式: salt_b64:nonce_b64:ciphertext_b64
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, private_key.encode(), None)
    
    return f"{base64.b64encode(salt).decode()}:{base64.b64encode(nonce).decode()}:{base64.b64encode(ciphertext).decode()}"

def generate_sm2_keys():
    """生成SM2密钥对"""
    from gmssl import sm2
    
    private_key = secrets.token_hex(32)
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key="")
    private_key_int = int(private_key, 16)
    g = sm2_crypt.ecc_table['g']
    public_key = sm2_crypt._kg(private_key_int, g)
    return private_key, public_key

def read_env():
    """读取.env文件"""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    
    if not os.path.exists(env_path):
        return {}
    
    env_vars = {}
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value
    return env_vars

def write_env(env_vars):
    """写入.env文件"""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    
    with open(env_path, 'w', encoding='utf-8') as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")

def get_encrypted_password():
    """交互式获取加密密码"""
    print("\n" + "="*60)
    print("SM2私钥加密设置")
    print("="*60)
    
    while True:
        password = getpass.getpass("请输入加密密码（至少8位）: ")
        if len(password) < 8:
            print("错误: 密码长度必须至少为8位")
            continue
        
        confirm = getpass.getpass("请再次输入密码: ")
        if password != confirm:
            print("错误: 两次输入的密码不一致")
            continue
        
        return password

def encrypt_existing_key():
    """加密现有的明文私钥"""
    env_vars = read_env()
    
    private_key = env_vars.get('SM2_PRIVATE_KEY')
    if not private_key:
        return False, "未找到明文私钥"
    
    if env_vars.get('SM2_PRIVATE_KEY_ENCRYPTED') == 'true':
        return False, "私钥已经加密"
    
    password = get_encrypted_password()
    
    print("\n正在加密私钥...")
    encrypted_data = encrypt_private_key(private_key, password)
    
    env_vars['SM2_PRIVATE_KEY_ENCRYPTED'] = 'true'
    env_vars['SM2_PRIVATE_KEY_ENCRYPTED_DATA'] = encrypted_data
    
    write_env(env_vars)
    
    print("\n私钥加密完成!")
    print("加密数据已写入.env文件")
    
    return True, "加密成功"

def init_new_key():
    """初始化新的SM2密钥对"""
    print("="*60)
    print("SM2密钥初始化")
    print("="*60)
    
    print("\n生成SM2密钥对...")
    private_key, public_key = generate_sm2_keys()
    print(f"私钥: {private_key[:20]}...")
    print(f"公钥: {public_key[:20]}...")
    
    env_vars = read_env()
    
    if env_vars.get('SM2_PRIVATE_KEY_ENCRYPTED') == 'true':
        print("\n检测到系统已配置加密私钥，跳过明文存储")
    else:
        print("\n存储明文私钥到.env文件...")
        env_vars['SM2_PRIVATE_KEY'] = private_key
        write_env(env_vars)
        print("明文私钥已写入.env文件")
    
    store_public_key(public_key)
    
    print("\n" + "="*60)
    print("SM2密钥初始化完成!")
    print("="*60)
    print(f"私钥: {private_key[:20]}...")
    print(f"公钥: {public_key[:20]}...")

def store_public_key(public_key):
    """将公钥存入system_config表"""
    import importlib.util
    
    app_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.py')
    spec = importlib.util.spec_from_file_location('app_module', app_py_path)
    app_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app_module)
    app = app_module.app
    
    from app import db
    from app.models.system_config import SystemConfig
    
    with app.app_context():
        db.create_all()
        existing_config = SystemConfig.query.filter_by(key='sm2_public_key').first()
        
        if existing_config:
            print("\nSM2公钥已存在于数据库")
        else:
            new_config = SystemConfig(key='sm2_public_key', value=public_key)
            db.session.add(new_config)
            db.session.commit()
            print("SM2公钥已存入数据库")

def main():
    """主函数"""
    env_vars = read_env()
    
    has_plain_key = 'SM2_PRIVATE_KEY' in env_vars
    is_encrypted = env_vars.get('SM2_PRIVATE_KEY_ENCRYPTED') == 'true'
    
    if has_plain_key and not is_encrypted:
        print("检测到系统中存在明文SM2私钥")
        response = input("是否要将私钥加密存储? (y/N): ").strip().lower()
        if response == 'y':
            success, msg = encrypt_existing_key()
            if success:
                print("\n加密成功! 请使用 start.ps1 启动后端服务")
            else:
                print(f"\n加密失败: {msg}")
                return
        else:
            print("\n跳过加密，继续使用明文私钥")
            print("可以直接运行 python app.py 启动")
    elif is_encrypted:
        print("检测到系统已配置加密SM2私钥")
        print("请使用 start.ps1 启动后端服务")
        print("或设置 SM2_PRIVATE_KEY_PASSWORD 环境变量后运行 python app.py")
    else:
        print("未找到SM2密钥，将生成新密钥...")
        init_new_key()

if __name__ == "__main__":
    main()
