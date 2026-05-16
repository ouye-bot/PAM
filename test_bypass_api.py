import requests
import json

# 测试绕行检测API
def test_bypass_detection():
    try:
        url = "http://localhost:5000/api/bypass/trigger"
        headers = {"Content-Type": "application/json"}
        
        print("调用绕行检测API...")
        response = requests.post(url, headers=headers, timeout=30)
        
        print(f"响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"检测结果: 检测了 {data['data']['total_assets']} 个资产，发现 {data['data']['detected_bypasses']} 个绕行")
        else:
            print("API调用失败")
    except Exception as e:
        print(f"错误: {str(e)}")

if __name__ == "__main__":
    test_bypass_detection()