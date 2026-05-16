import pymysql
from gmssl.sm3 import sm3_hash

# 数据库连接配置
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',
    'database': 'pam_system',
    'charset': 'utf8mb4'
}

def calculate_hash(log_type, operator, source_ip, target_asset, operation_detail, result, timestamp, previous_hash):
    """计算审计日志的哈希值"""
    data_to_hash = f"{log_type}|{operator}|{source_ip}|{target_asset}|{operation_detail}|{result}|{timestamp}|{previous_hash}"
    data_list = list(data_to_hash.encode('utf-8'))
    return sm3_hash(data_list)

# 连接数据库
conn = pymysql.connect(**db_config)
cursor = conn.cursor()

# 查询所有审计日志，按ID顺序排列
cursor.execute("SELECT id, log_type, operator, source_ip, target_asset, operation_detail, result, timestamp, previous_hash, current_hash FROM audit_logs ORDER BY id")
logs = cursor.fetchall()

# 重新计算并修复哈希链
previous_hash = ''
for log in logs:
    log_id, log_type, operator, source_ip, target_asset, operation_detail, result, timestamp, previous_hash_stored, current_hash_stored = log

    # 重新计算哈希值
    calculated_hash = calculate_hash(log_type, operator, source_ip, target_asset, operation_detail, result, str(timestamp), previous_hash)

    # 更新current_hash和previous_hash
    cursor.execute("UPDATE audit_logs SET current_hash=%s, previous_hash=%s WHERE id=%s",
                   (calculated_hash, previous_hash, log_id))
    print(f"修复ID={log_id}的审计日志: previous_hash={previous_hash[:20] if previous_hash else 'empty'}..., current_hash={calculated_hash[:20]}...")

    # 更新previous_hash为当前日志的current_hash
    previous_hash = calculated_hash

conn.commit()
print("\n哈希链修复完成")

cursor.close()
conn.close()
