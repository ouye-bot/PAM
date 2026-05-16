import socket
import time

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
        
        # 接收代理服务器的握手包
        handshake_data = proxy_socket.recv(1024)
        print(f"Received handshake data, length: {len(handshake_data)}")
        
        # 准备认证包（模拟MySQL客户端）
        # 注意：这是一个简化的认证包，实际MySQL认证包格式更复杂
        # 我们使用token作为密码
        token = "dae1c3e0-6b77-4b13-b3a0-a8e16b12"
        auth_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a' + f"token:{token}".encode('utf-8')
        
        # 发送认证包
        proxy_socket.send(auth_data)
        print(f"Sent authentication data, length: {len(auth_data)}")
        
        # 接收认证响应
        auth_response = proxy_socket.recv(1024)
        print(f"Received auth response, length: {len(auth_response)}")
        
        # 发送SQL查询
        sql_query = "SELECT 1;".encode('utf-8')
        # MySQL COM_QUERY命令
        query_packet = b'\x00\x00\x00\x00\x03' + sql_query
        proxy_socket.send(query_packet)
        print(f"Sent SQL query, length: {len(query_packet)}")
        
        # 接收查询结果
        result = proxy_socket.recv(4096)
        print(f"Received query result, length: {len(result)}")
        print(f"Result: {result}")
        
        print("Test completed successfully")
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        proxy_socket.close()

if __name__ == "__main__":
    test_mysql_proxy()
