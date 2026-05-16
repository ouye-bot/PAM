import pymysql
import sys

TOKEN = sys.argv[1] if len(sys.argv) > 1 else "2bcac69d3a0f4f0e8f8e62627485b9e541815d5d43af4523b7b14d1bbfd89150"

conn = pymysql.connect(
    host='127.0.0.1',
    port=3307,
    user='token',
    password=TOKEN,
    database='mysql',
    autocommit=True
)

try:
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1")
    result = cursor.fetchall()
    print(f"[TEST] SELECT 1 => {result}")
    
    cursor.execute("SELECT VERSION()")
    result = cursor.fetchall()
    print(f"[TEST] SELECT VERSION() => {result}")
    
    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()
    db_list = [r[0] for r in databases]
    print(f"[TEST] SHOW DATABASES => {db_list}")
    
    cursor.execute("SELECT 1 + 1 AS sum")
    result = cursor.fetchall()
    print(f"[TEST] SELECT 1+1 => {result}")
    
    print("[TEST] 所有查询成功!")
    
except Exception as e:
    print(f"[TEST ERROR] {e}")

finally:
    conn.close()
