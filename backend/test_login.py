import requests
import json

BASE_URL = "http://localhost:5000/api"

# 登录获取token
def login():
    url = f"{BASE_URL}/auth/login"
    data = {"username": "admin", "password": "admin123"}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        print(f"登录响应状态码: {response.status_code}")
        print(f"登录响应内容: {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"解析后的JSON: {result}")
            if result.get('code') == 200:
                return result.get('token')
    except Exception as e:
        print(f"登录失败: {e}")
    return None

if __name__ == "__main__":
    print("1. 正在登录...")
    token = login()
    if not token:
        print("登录失败，无法继续")
        exit(1)
    print(f"登录成功，Token: {token}")
