#!/usr/bin/env python3
"""
检查资产详细状态
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
    
    # 检查所有资产
    all_assets = Asset.query.all()
    print("=== 所有资产详细状态 ===")
    for asset in all_assets:
        print(f"资产: {asset.ip}:{asset.ssh_port}")
        print(f"  ID: {asset.id}")
        print(f"  状态: {asset.status!r}")  # 使用!r显示原始值
        print(f"  连通性: {asset.connectivity!r}")
        print(f"  最后检测时间: {asset.last_check_time}")
        print(f"  OS类型: {asset.os_type}")
        print(f"  主机名: {asset.hostname}")
        print()
    
    # 检查活跃资产
    active_assets = Asset.query.filter_by(status='active').all()
    print(f"\n=== 活跃资产 ({len(active_assets)}) ===")
    for asset in active_assets:
        print(f"  {asset.ip}:{asset.ssh_port}")
    
    # 检查API返回的数据格式
    print("\n=== API返回格式模拟 ===")
    api_result = []
    for asset in all_assets:
        asset_data = {
            'id': asset.id,
            'ip': asset.ip,
            'hostname': asset.hostname or asset.ip,
            'os_type': asset.get_display_os_type(),
            'ssh_port': asset.ssh_port,
            'status': asset.status or 'active',  # 这里是关键！
            'connectivity': asset.connectivity or 'unknown',
            'last_check_time': asset.last_check_time.strftime('%Y-%m-%d %H:%M:%S') if asset.last_check_time else None,
            'credentials': [{'id': cred.id, 'account_name': cred.account_name} for cred in asset.credentials]
        }
        api_result.append(asset_data)
    
    print("API返回的资产数量:", len(api_result))
    for asset in api_result:
        print(f"  {asset['ip']}:{asset['ssh_port']} - 状态: {asset['status']}, 连通性: {asset['connectivity']}")
