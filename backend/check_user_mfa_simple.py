#!/usr/bin/env python3
"""
检查用户MFA状态（简化版）
"""

import os
import sys

# 切换到backend目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 执行SQL查询直接检查数据库
import pymysql
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 数据库配置
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', '123456'),
    'database': os.getenv('DB_NAME', 'pam_system')
}

try:
    # 连接数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    
    print("用户MFA状态检查：")
    print("-" * 60)
    
    # 查询所有用户
    cursor.execute("SELECT id, username, totp_enabled, totp_secret FROM users")
    users = cursor.fetchall()
    
    for user in users:
        user_id, username, totp_enabled, totp_secret = user
        print(f"用户: {username}")
        print(f"  ID: {user_id}")
        print(f"  MFA启用: {totp_enabled}")
        print(f"  MFA密钥: {totp_secret}")
        print("-" * 60)
    
    # 特别检查admin用户
    cursor.execute("SELECT totp_enabled, totp_secret FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()
    if admin:
        totp_enabled, totp_secret = admin
        print("\nAdmin用户详细信息:")
        print(f"  MFA启用状态: {totp_enabled}")
        print(f"  MFA密钥是否存在: {bool(totp_secret)}")
    else:
        print("\n未找到admin用户")
    
finally:
    if 'cursor' in locals():
        cursor.close()
    if 'conn' in locals():
        conn.close()
