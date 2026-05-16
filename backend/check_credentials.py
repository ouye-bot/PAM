#!/usr/bin/env python3
"""
检查凭证密码获取
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
    from app.models import Asset, Credential
    from app.services.crypto_service import decrypt_password
    
    # 检查资产数量
    all_assets = Asset.query.all()
    print(f"总资产数: {len(all_assets)}")
    
    # 检查活跃资产
    active_assets = Asset.query.filter_by(status='active').all()
    print(f"活跃资产数: {len(active_assets)}")
    
    # 检查每个资产的凭证
    print("\n=== 检查凭证密码 ===")
    for asset in active_assets:
        print(f"\n资产: {asset.ip}:{asset.ssh_port}")
        
        if not asset.credentials:
            print("  无关联凭证")
            continue
        
        for credential in asset.credentials:
            print(f"  凭证ID: {credential.id}")
            print(f"  账号: {credential.account_name}")
            print(f"  密码密文: {credential.password}")
            
            # 测试get_password方法
            try:
                password = credential.get_password()
                print(f"  解密后密码: '{password}'")
                print(f"  密码长度: {len(password) if password else 0}")
            except Exception as e:
                print(f"  解密失败: {str(e)}")
                import traceback
                traceback.print_exc()
            
            # 直接测试解密函数
            try:
                if credential.password:
                    decrypted = decrypt_password(credential.password)
                    print(f"  直接解密结果: '{decrypted}'")
            except Exception as e:
                print(f"  直接解密失败: {str(e)}")
