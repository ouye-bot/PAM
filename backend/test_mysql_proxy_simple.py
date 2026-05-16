import socket

# 测试MySQL代理连接
def test_mysql_proxy():
    print("Testing MySQL proxy connection...")
    
    # 连接到代理服务器
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.settimeout(10)
    
    try:
        # 连接到代理端口
        proxy_socket.connect(('127.0.0.1', 33070))
        print("Connected to proxy server")
        
        # 发送Token
        token = "c4673f30-17bc-4b8d-a6f7-d87130b96c88"
        proxy_socket.send(f"token:{token}".encode('utf-8'))
        print(f"Sent token: {token}")
        
        # 接收连接响应
        response = proxy_socket.recv(1024)
        print(f"Received response: {response.decode('utf-8')}")
        
        # 发送SQL查询
        sql_queries = [
            "SELECT 1;",
            "SHOW DATABASES;",
            "SELECT NOW();"
        ]
        
        for sql in sql_queries:
            print(f"\nSending SQL: {sql}")
            proxy_socket.send(sql.encode('utf-8'))
            
            # 接收查询结果
            result = proxy_socket.recv(4096)
            print(f"Received result: {result.decode('utf-8')}")
        
        # 发送退出命令
        print("\nSending exit command")
        proxy_socket.send("exit".encode('utf-8'))
        
        print("Test completed successfully")
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        proxy_socket.close()

if __name__ == "__main__":
    test_mysql_proxy()
