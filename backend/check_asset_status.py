#!/usr/bin/env python3
"""
检查资产状态
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
    from app.models import Asset
    assets = Asset.query.all()
    print("=== 资产状态 ===")
    for asset in assets:
        print(f"资产: {asset.ip}:{asset.ssh_port}")
        print(f"  状态: {asset.status}")
        print(f"  连通性: {asset.connectivity}")
        print(f"  最后检测时间: {asset.last_check_time}")
        print()
