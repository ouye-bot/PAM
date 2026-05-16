import hashlib
import bcrypt


def hash_password(password: str) -> str:
    """对明文密码进行 bcrypt 哈希，返回 $2b$12$... 格式的哈希字符串

    先对密码做 SHA-256 预哈希，再输入 bcrypt（解决 bcrypt 72字节限制）。
    兼容 bcrypt 标准格式，不影响迁移脚本对存量 $2b$ 的判断。
    """
    pre = hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')
    return bcrypt.hashpw(pre, bcrypt.gensalt(rounds=12)).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """验证明文密码是否与 bcrypt 哈希匹配"""
    pre = hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')
    return bcrypt.checkpw(pre, hashed.encode('utf-8'))
