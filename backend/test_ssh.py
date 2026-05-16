import paramiko
import socket

def test_ssh(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"尝试 {username}:{password}")

        ssh.connect(hostname=ip, port=port, username=username, password=password, timeout=10)

        print("SSH连接成功!")

        _, stdout, _ = ssh.exec_command("hostname")
        hostname = stdout.read().decode().strip()
        print(f"Hostname: {hostname}")

        _, stdout, _ = ssh.exec_command("cat /etc/os-release | grep PRETTY_NAME")
        os_info = stdout.read().decode().strip()
        print(f"OS: {os_info}")

        ssh.close()
        return True
    except Exception as e:
        print(f"失败: {str(e)[:50]}")
        return False

passwords = ["123456", "root", "admin", "123", "root123", "password"]
for pwd in passwords:
    if test_ssh("localhost", 2222, "root", pwd):
        print(f"成功密码: {pwd}")
        break
