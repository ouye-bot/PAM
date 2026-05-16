import os
import sys
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 直接导入app.py中的app和db
import sys
sys.path.append('.')
from app import app, db
from app.models import Asset

with app.app_context():
    print("=== 资产端口检查 ===")

    # 查询所有资产
    assets = Asset.query.all()

    if not assets:
        print("没有找到资产")
        sys.exit(0)

    print(f"共找到 {len(assets)} 个资产")
    print("-" * 60)

    for asset in assets:
        print(f"资产ID: {asset.id}")
        print(f"IP: {asset.ip}")
        print(f"主机名: {asset.hostname}")
        print(f"SSH端口: {asset.ssh_port} (类型: {type(asset.ssh_port)})")
        print(f"操作系统: {asset.os_type}")
        print(f"状态: {asset.status}")
        print(f"连接性: {asset.connectivity}")
        print("-" * 60)

    print("检查完成")
