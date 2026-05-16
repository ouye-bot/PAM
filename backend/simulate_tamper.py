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

# 查询最新的审计日志
cursor.execute("SELECT id, log_type, operation_detail FROM audit_logs ORDER BY id DESC LIMIT 1")
latest_log = cursor.fetchone()

if latest_log:
    print(f"最新审计日志: ID={latest_log[0]}, log_type={latest_log[1]}, detail={latest_log[2]}")

    # 模拟篡改：将最新日志的current_hash修改为无效值
    cursor.execute("UPDATE audit_logs SET current_hash='invalid_hash' WHERE id=%s", (latest_log[0],))
    conn.commit()
    print(f"已修改ID为{latest_log[0]}的审计日志的current_hash为'invalid_hash'")
else:
    print("没有找到审计日志")

cursor.close()
conn.close()
