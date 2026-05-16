import socket
import time

# 测试MySQL代理连接
def test_proxy_connection():
    print("Testing MySQL proxy connection...")
    
    # 连接到代理服务器
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.settimeout(5)
    
    try:
        # 连接到代理端口
        proxy_socket.connect(('127.0.0.1', 33070))
        print("Connected to proxy server")
        
        # 接收代理服务器的握手包
        handshake_data = proxy_socket.recv(1024)
        print(f"Received handshake data, length: {len(handshake_data)}")
        
        # 发送一个简单的认证包（模拟MySQL客户端）
        # 注意：这只是一个简单的测试，实际MySQL认证包格式更复杂
        auth_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'
        proxy_socket.send(auth_data)
        print(f"Sent authentication data, length: {len(auth_data)}")
        
        # 接收响应
        response = proxy_socket.recv(1024)
        print(f"Received response, length: {len(response)}")
        
        print("Test completed successfully")
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        proxy_socket.close()

if __name__ == "__main__":
    test_proxy_connection()
