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
        
        if response.status_code == 200:
            result = response.json()
            if result.get('code') == 200:
                return result.get('token')
    except Exception as e:
        print(f"登录失败: {e}")
    return None

# 触发绕行检测
def trigger_bypass_detection(token):
    url = f"{BASE_URL}/bypass/trigger"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    try:
        response = requests.post(url, headers=headers, timeout=60)
        print(f"绕行检测响应状态码: {response.status_code}")
        print(f"绕行检测响应内容: {response.text}")
        return response.json()
    except Exception as e:
        print(f"触发绕行检测失败: {e}")
    return None

if __name__ == "__main__":
    print("1. 正在登录...")
    token = login()
    if not token:
        print("登录失败，无法继续")
        exit(1)
    print(f"登录成功，Token获取成功")

    print("\n2. 正在触发绕行检测...")
    result = trigger_bypass_detection(token)
