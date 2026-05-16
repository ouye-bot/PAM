import paramiko
import time

host = 'localhost'
port = 2221
username = 'root'
password = 'Z=7QDg88&:6Ejpl'

print(f"正在连接到 {host}:{port} ...")

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    client.connect(host, port=port, username=username, password=password, timeout=10)
    print("SSH连接成功！")

    stdin, stdout, stderr = client.exec_command('whoami')
    print(f"执行 whoami: {stdout.read().decode().strip()}")

    time.sleep(1)

    stdin, stdout, stderr = client.exec_command('uptime')
    print(f"执行 uptime: {stdout.read().decode().strip()}")

    print("关闭SSH连接...")
    client.close()
    print("SSH连接已关闭")
except Exception as e:
    print(f"SSH连接失败: {e}")