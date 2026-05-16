import paramiko

host = "localhost"
port = 2221
username = "root"
password = "root"  # 根据您的配置调整

try:
    print(f"连接到 {host}:{port}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password, timeout=10)
    print("连接成功！")
    
    print("\n执行 last -i 命令：")
    stdin, stdout, stderr = ssh.exec_command("last -i")
    output = stdout.read().decode()
    print(output)
    
    ssh.close()
except Exception as e:
    print(f"错误：{e}")
    import traceback
    traceback.print_exc()