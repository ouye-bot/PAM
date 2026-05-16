import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app import create_app, db
from app.models import Asset, Credential
from app.services.crypto_service import CryptoService
import paramiko

app = create_app()
with app.app_context():
    assets = Asset.query.filter_by(status='active').all()
    
    for asset in assets:
        if asset.ssh_port == 2221:
            print(f"找到目标资产: {asset.ip}:{asset.ssh_port}")
            credential = asset.credentials[0]
            password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
            
            try:
                print(f"连接到 {asset.ip}:{asset.ssh_port}...")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(asset.ip, port=asset.ssh_port, username=credential.account_name, password=password, timeout=10)
                print("连接成功！")
                
                print("\n执行 last -i 命令：")
                stdin, stdout, stderr = ssh.exec_command("last -i")
                output = stdout.read().decode()
                print(output)
                
                print("\n执行 last 命令：")
                stdin, stdout, stderr = ssh.exec_command("last")
                output = stdout.read().decode()
                print(output)
                
                ssh.close()
            except Exception as e:
                print(f"错误：{e}")
                import traceback
                traceback.print_exc()