import pymysql

# 数据库连接配置
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',
    'database': 'pam_system',
    'charset': 'utf8mb4'
}

# 连接数据库
conn = pymysql.connect(**db_config)
cursor = conn.cursor()

# 查询所有资产和凭证
cursor.execute("SELECT id, ip, os_type FROM assets")
assets = cursor.fetchall()
print("资产列表:")
for asset in assets:
    print(f"  ID={asset[0]}, IP={asset[1]}, OS={asset[2]}")

# 查询改密任务
cursor.execute("""
    SELECT rt.id, rt.credential_id, rt.executed_at, rt.status, c.account_name, a.ip
    FROM rotation_tasks rt
    JOIN credentials c ON rt.credential_id = c.id
    JOIN assets a ON c.asset_id = a.id
    ORDER BY rt.executed_at DESC
    LIMIT 10
""")
tasks = cursor.fetchall()
print("\n改密任务记录:")
for task in tasks:
    print(f"  ID={task[0]}, credential_id={task[1]}, executed_at={task[2]}, status={task[3]}, account={task[4]}, asset_ip={task[5]}")

cursor.close()
conn.close()
