import urllib.request
import json

BASE_URL = "http://localhost:5000/api"

def login():
    url = f"{BASE_URL}/auth/login"
    data = json.dumps({"username": "admin", "password": "admin123"}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            if result.get('code') == 200:
                return result.get('token')
    except Exception as e:
        print(f"登录失败: {e}")
    return None

def trigger_bypass_detection(token):
    url = f"{BASE_URL}/bypass/trigger"
    data = json.dumps({}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            result = response.read().decode('utf-8')
            print(f"绕行检测响应: {result}")
            return json.loads(result)
    except urllib.error.HTTPError as e:
        print(f"HTTP错误: {e.code} - {e.reason}")
        print(f"响应内容: {e.read().decode('utf-8')}")
    except Exception as e:
        print(f"请求失败: {e}")
    return None

def get_alerts(token):
    url = f"{BASE_URL}/bypass/alerts"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = response.read().decode('utf-8')
            print(f"告警列表响应: {result}")
            return json.loads(result)
    except Exception as e:
        print(f"查询告警失败: {e}")
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

    print("\n3. 查询绕行告警...")
    alerts = get_alerts(token)