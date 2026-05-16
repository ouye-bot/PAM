#!/usr/bin/env python3
"""
初始化密码策略配置
"""
import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

app_py_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py')
spec = importlib.util.spec_from_file_location('app_module', app_py_path)
app_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_module)
app = app_module.app

with app.app_context():
    from app import db
    from app.models import SystemConfig
    
    # 创建表
    db.create_all()
    
    # 默认策略
    default_policies = [
        {'key': 'pwd_min_length', 'value': '16'},
        {'key': 'pwd_require_upper', 'value': 'true'},
        {'key': 'pwd_require_lower', 'value': 'true'},
        {'key': 'pwd_require_digit', 'value': 'true'},
        {'key': 'pwd_require_special', 'value': 'true'},
        {'key': 'pwd_special_chars', 'value': '!@#$%^&*()_+-=[]{}|;:,.<>?'}
    ]
    
    # 插入或更新默认策略
    for policy in default_policies:
        config = SystemConfig.query.filter_by(key=policy['key']).first()
        if not config:
            config = SystemConfig(**policy)
            db.session.add(config)
            print(f"Added policy: {policy['key']} = {policy['value']}")
        else:
            config.value = policy['value']
            print(f"Updated policy: {policy['key']} = {policy['value']}")
    
    db.session.commit()
    print("\n密码策略初始化完成！")
