#!/usr/bin/env python3
"""
手动执行资产连通性巡检
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

# 获取app实例
app = app_module.app

with app.app_context():
    from app.models import Asset, Credential
    from app.services.crypto_service import CryptoService
    import paramiko
    import socket
    from datetime import datetime
    from app import db
    
    print("=== 手动执行资产连通性巡检 ===")
    
    online_count = 0
    offline_count = 0
    error_count = 0
    
    active_assets = Asset.query.filter_by(status='active').all()
    print(f"发现 {len(active_assets)} 个活跃资产")
    
    for asset in active_assets:
        try:
            if not asset.credentials:
                print(f"资产 {asset.ip} 无关联凭证，跳过")
                asset.connectivity = 'unknown'
                asset.last_check_time = datetime.now()
                error_count += 1
                continue
            
            credential = asset.credentials[0]
            
            # 测试SSH连接
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            timeout = 5
            
            print(f"测试资产: {asset.ip}:{asset.ssh_port}")
            print(f"  账号: {credential.account_name}")
            
            password = credential.get_password()
            if not password:
                print("  密码解密失败")
                asset.connectivity = 'unknown'
                asset.last_check_time = datetime.now()
                error_count += 1
                continue
            
            print(f"  密码: {'*' * len(password)}")
            
            client.connect(
                hostname=asset.ip,
                port=asset.ssh_port,
                username=credential.account_name,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            print("  连接成功！")
            
            # 执行echo命令
            stdin, stdout, stderr = client.exec_command('echo ok', timeout=timeout)
            result = stdout.read().decode().strip()
            print(f"  执行命令结果: '{result}'")
            
            if result == 'ok':
                asset.connectivity = 'online'
                online_count += 1
                print("  资产在线")
            else:
                asset.connectivity = 'offline'
                offline_count += 1
                print("  资产离线")
            
            client.close()
            asset.last_check_time = datetime.now()
            
        except paramiko.AuthenticationException:
            print("  认证失败")
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            offline_count += 1
        except paramiko.SSHException as e:
            print(f"  SSH异常: {str(e)}")
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            offline_count += 1
        except socket.timeout:
            print("  连接超时")
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            offline_count += 1
        except socket.error as e:
            print(f"  Socket错误: {str(e)}")
            asset.connectivity = 'offline'
            asset.last_check_time = datetime.now()
            offline_count += 1
        except Exception as e:
            print(f"  检测失败: {str(e)}")
            import traceback
            traceback.print_exc()
            asset.connectivity = 'unknown'
            asset.last_check_time = datetime.now()
            error_count += 1
            continue
    
    db.session.commit()
    print(f"\n资产连通性检测完成，在线 {online_count}，离线 {offline_count}，异常 {error_count}")
    
    # 显示结果
    print("\n=== 巡检后资产状态 ===")
    for asset in Asset.query.all():
        print(f"资产 {asset.ip}:{asset.ssh_port}: {asset.connectivity}")
        print(f"  最后检测时间: {asset.last_check_time}")
