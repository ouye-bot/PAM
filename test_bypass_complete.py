import requests
import sys

BASE_URL = "http://localhost:5000/api"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def test_bypass():
    print("=" * 60)
    print("PAM 绕行检测测试脚本")
    print("=" * 60)

    print("\n[1] 正在登录...")
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    if login_resp.status_code != 200:
        print(f"登录失败: {login_resp.text}")
        sys.exit(1)
    token = login_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}
    print(f"登录成功, Token: {token[:20]}...")

    print("\n[2] 正在触发绕行检测...")
    trigger_resp = requests.post(f"{BASE_URL}/bypass/trigger", headers=headers)
    if trigger_resp.status_code != 200:
        print(f"触发失败: {trigger_resp.text}")
        sys.exit(1)
    data = trigger_resp.json()
    print(f"检测结果: 总资产 {data['data']['total_assets']}, 发现绕行 {data['data']['detected_bypasses']}")

    print("\n[3] 获取告警列表...")
    alerts_resp = requests.get(f"{BASE_URL}/bypass/alerts", headers=headers)
    if alerts_resp.status_code == 200:
        alerts = alerts_resp.json().get("data", [])
        print(f"最近告警: {len(alerts)} 条")
        for alert in alerts[:3]:
            print(f"  - {alert['time']} | {alert['asset']} | {alert['message']}")
    else:
        print(f"获取告警失败: {alerts_resp.text}")

    print("\n" + "=" * 60)
    if data['data']['detected_bypasses'] > 0:
        print("测试结果: 发现绕行 (PASS)")
    else:
        print("测试结果: 未发现绕行 (FAIL)")
    print("=" * 60)

if __name__ == "__main__":
    test_bypass()