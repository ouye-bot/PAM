#!/usr/bin/env python3
"""
检查用户MFA状态
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 直接从app.py文件导入应用和db
import app as app_module
from app.models import User

# 获取应用对象
app = app_module.app
# 获取db对象
db = app_module.db

with app.app_context():
    # 检查所有用户
    users = User.query.all()
    print("用户MFA状态检查：")
    print("-" * 60)
    
    for user in users:
        print(f"用户: {user.username}")
        print(f"  ID: {user.id}")
        print(f"  MFA启用: {user.totp_enabled}")
        print(f"  MFA密钥: {user.totp_secret}")
        print("-" * 60)
    
    # 特别检查admin用户
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print("\nAdmin用户详细信息:")
        print(f"  MFA启用状态: {admin.totp_enabled}")
        print(f"  MFA密钥是否存在: {bool(admin.totp_secret)}")
    else:
        print("\n未找到admin用户")
