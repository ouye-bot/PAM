#!/usr/bin/env python3
"""
检查密码策略配置
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
    from app.models import SystemConfig

    configs = SystemConfig.query.all()
    print("=== 密码策略配置 ===")
    for config in configs:
        print(f"  {config.key} = {config.value!r}")
