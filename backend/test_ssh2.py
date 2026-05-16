import paramiko

def test_ssh():
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("尝试连接 localhost:2223")
        ssh.connect('localhost', 2223, 'root', '123456', timeout=10)
        print("连接成功！")
        
        # 测试命令
        stdin, stdout, stderr = ssh.exec_command('hostname')
        hostname = stdout.read().decode().strip()
        print(f"主机名: {hostname}")
        
        stdin, stdout, stderr = ssh.exec_command('cat /etc/os-release | grep PRETTY_NAME')
        os_info = stdout.read().decode().strip()
        print(f"系统: {os_info}")
        
        ssh.close()
        return True
    except Exception as e:
        print(f"连接失败: {str(e)}")
        return False

test_ssh()
