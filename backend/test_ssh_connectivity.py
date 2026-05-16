#!/usr/bin/env python3
"""
测试资产连通性检测
"""
import os
import sys
import paramiko
import socket

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
    
    # 检查资产数量
    all_assets = Asset.query.all()
    print(f"总资产数: {len(all_assets)}")
    
    # 检查活跃资产
    active_assets = Asset.query.filter_by(status='active').all()
    print(f"活跃资产数: {len(active_assets)}")
    
    # 测试每个资产的SSH连接
    print("\n=== 测试SSH连接 ===")
    for asset in active_assets:
        print(f"\n测试资产: {asset.ip}:{asset.ssh_port}")
        print(f"  状态: {asset.status}")
        print(f"  连通性: {asset.connectivity}")
        print(f"  最后检测时间: {asset.last_check_time}")
        
        if not asset.credentials:
            print("  无关联凭证，跳过测试")
            continue
        
        credential = asset.credentials[0]
        print(f"  凭证账号: {credential.account_name}")
        
        # 测试SSH连接
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            timeout = 5
            
            print(f"  尝试连接: {asset.ip}:{asset.ssh_port}")
            client.connect(
                hostname=asset.ip,
                port=asset.ssh_port,
                username=credential.account_name,
                password=credential.get_password() if hasattr(credential, 'get_password') else None,
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
                print("  命令执行成功，资产在线")
            else:
                print("  命令执行失败，资产离线")
            
            client.close()
            
        except paramiko.AuthenticationException:
            print("  认证失败")
        except paramiko.SSHException as e:
            print(f"  SSH异常: {str(e)}")
        except socket.timeout:
            print("  连接超时")
        except socket.error as e:
            print(f"  Socket错误: {str(e)}")
        except Exception as e:
            print(f"  检测失败: {str(e)}")
            import traceback
            traceback.print_exc()
