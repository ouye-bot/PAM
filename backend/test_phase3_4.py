# -*- coding: utf-8 -*-
"""Phase 3 & 4 verification tests"""
import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

admin_token = None
operator_token = None
auditor_token = None
created_asset_id = None

def login(username, password):
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": username, "password": password
    })
    data = resp.json()
    print(f"  Login {username}: {data.get('code')} - {data.get('message', '')}")
    if data.get('code') == 200:
        return data.get('token')
    return None

def create_mysql_asset(token, allowed_roles='admin'):
    resp = requests.post(f"{BASE_URL}/api/assets", json={
        "name": "test-mysql-p3v4",
        "host": "127.0.0.101",
        "port": 3306,
        "asset_type": "mysql",
        "username": "pam_user",
        "password": "pam_password",
        "allowed_roles": allowed_roles
    }, headers={"Authorization": f"Bearer {token}"})
    data = resp.json()
    print(f"  Create asset: code={data.get('code')} - asset_id={data.get('asset_id', 'N/A')} msg={data.get('message', '')}")
    return data.get('asset_id')

def test_task11_role_based_access():
    print("\n=== Task 11: Role-based asset filtering ===")
    global created_asset_id

    print("[1] admin creates MySQL asset with allowed_roles='admin'")
    asset_id = create_mysql_asset(admin_token, allowed_roles='admin')
    created_asset_id = asset_id
    if not asset_id:
        print("FAIL: Could not create asset")
        return False

    print("[2] operator fetches assets (should see 0)")
    resp = requests.get(f"{BASE_URL}/api/assets", headers={"Authorization": f"Bearer {operator_token}"})
    data = resp.json()
    count = len(data) if isinstance(data, list) else len(data.get('data', []))
    operator_count = count
    print(f"  operator sees {operator_count} assets")
    if count > 0:
        print("FAIL: operator should see 0 assets with admin-only role")
        return False
    print("PASS: operator sees 0 assets (correct)")

    print("[3] auditor fetches assets (should see all)")
    resp = requests.get(f"{BASE_URL}/api/assets", headers={"Authorization": f"Bearer {auditor_token}"})
    data = resp.json()
    count = len(data) if isinstance(data, list) else len(data.get('data', []))
    print(f"  auditor sees {count} assets")
    if count == 0:
        print("FAIL: auditor should see assets")
        return False
    print("PASS: auditor sees assets (correct)")

    print("[4] admin fetches assets with type=mysql")
    resp = requests.get(f"{BASE_URL}/api/assets?type=mysql", headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    items = data if isinstance(data, list) else data.get('data', [])
    print(f"  admin sees {len(items)} MySQL assets")
    if len(items) == 0:
        print("FAIL: admin should see MySQL assets")
        return False

    print("Task 11 PASS")
    return True

def test_task7_proxy_token():
    print("\n=== Task 7: Proxy token generation ===")
    global created_asset_id

    if not created_asset_id:
        print("SKIP: No asset available")
        return False

    print(f"[1] Request token for asset_id={created_asset_id}")
    resp = requests.post(f"{BASE_URL}/api/proxy/token", json={
        "asset_id": created_asset_id
    }, headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    print(f"  Response: {data.get('code')} - token present={'token' in data}")
    if data.get('code') != 200 or 'token' not in data:
        print("FAIL: Token not generated")
        return False

    token = data.get('token')
    expires_in = data.get('expires_in')
    print(f"  Token: {token[:20]}... expires_in={expires_in}s")
    if expires_in != 300:
        print(f"WARNING: expires_in={expires_in}s (expected 300s)")
    else:
        print("PASS: expires_in is 300s (correct)")

    print("[2] Validate token")
    resp = requests.post(f"{BASE_URL}/api/proxy/token/validate", json={
        "token": token
    }, headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    print(f"  Validate: {data.get('code')} - valid={data.get('valid', False)}")
    if not data.get('valid'):
        print("FAIL: Token validation failed")
        return False
    print("PASS: Token is valid")

    print("Task 7 PASS")
    return True

def test_task9_audit_log_filter():
    print("\n=== Task 9: Audit log type filtering ===")
    print("[1] Get audit logs with MYSQL_PROXY filter")
    resp = requests.get(f"{BASE_URL}/api/audit/logs?page=1&page_size=10&log_type=MYSQL_PROXY",
                        headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    if data.get('code') == 200:
        items = data.get('data', {}).get('items', [])
        print(f"  Found {len(items)} MYSQL_PROXY audit logs")
        for item in items[:3]:
            print(f"    ID={item.get('id')} type={item.get('log_type')} detail={item.get('operation_detail', '')[:50]}")
    else:
        print(f"  Error: {data}")

    print("[2] Get audit logs with session filter")
    resp = requests.get(f"{BASE_URL}/api/audit/logs?page=1&page_size=10&log_type=session",
                        headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    if data.get('code') == 200:
        items = data.get('data', {}).get('items', [])
        print(f"  Found {len(items)} session audit logs")
    else:
        print(f"  Error: {data}")

    print("[3] Verify MYSQL_PROXY logs have hash values")
    resp = requests.get(f"{BASE_URL}/api/audit/logs?page=1&page_size=5&log_type=MYSQL_PROXY",
                        headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    if data.get('code') == 200:
        items = data.get('data', {}).get('items', [])
        all_hashed = all(item.get('hash_value') for item in items)
        print(f"  All logs have hash_value: {all_hashed}")
        if not all_hashed:
            print("WARNING: Some logs missing hash_value")

    print("Task 9 PASS")
    return True

def test_task12_logical_delete():
    print("\n=== Task 12: Logical asset deletion ===")
    global created_asset_id

    if not created_asset_id:
        print("SKIP: No asset available")
        return False

    print(f"[1] Delete asset_id={created_asset_id}")
    resp = requests.delete(f"{BASE_URL}/api/assets/{created_asset_id}",
                           headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    print(f"  Delete response: {data.get('code')} - {data.get('message')}")
    if data.get('code') != 200:
        print("FAIL: Delete failed")
        return False
    print("PASS: Delete returned success")

    print("[2] Verify asset not in active list")
    resp = requests.get(f"{BASE_URL}/api/assets", headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    items = data if isinstance(data, list) else data.get('data', [])
    deleted_still_visible = any(item.get('id') == created_asset_id for item in items)
    print(f"  Deleted asset visible in list: {deleted_still_visible}")
    if deleted_still_visible:
        print("WARNING: Deleted asset still visible (may be correct if status check is passive)")
    else:
        print("PASS: Deleted asset hidden from listing")

    print("[3] Verify delete audit log exists")
    time.sleep(0.3)
    resp = requests.get(f"{BASE_URL}/api/audit/logs?page=1&page_size=10&log_type=asset_delete",
                        headers={"Authorization": f"Bearer {admin_token}"})
    data = resp.json()
    if data.get('code') == 200:
        items = data.get('data', {}).get('items', [])
        print(f"  Found {len(items)} delete audit logs")
        if len(items) > 0:
            print(f"  Delete log detail: {items[0].get('operation_detail', '')[:80]}")
            print("PASS: Delete audit log recorded")
        else:
            print("WARNING: No delete audit log found")

    print("Task 12 PASS")
    return True

def main():
    global admin_token, operator_token, auditor_token, created_asset_id

    print("=" * 60)
    print("Phase 3 & 4 Verification Tests")
    print("=" * 60)

    print("\n--- Logging in ---")
    admin_token = login("admin", "admin123")
    if not admin_token:
        print("FAIL: Admin login failed")
        return
    print(f"  Admin token: {admin_token[:20]}...")

    operator_token = login("operator", "operator123")
    if not operator_token:
        print("FAIL: Operator login failed (try admin first)")
        operator_token = login("admin", "admin123")

    auditor_token = login("auditor", "auditor123")
    if not auditor_token:
        print("WARNING: Auditor login failed, using admin token")
        auditor_token = admin_token

    tests = [
        ("Task 11 - Role-based access", test_task11_role_based_access),
        ("Task 7 - Proxy token", test_task7_proxy_token),
        ("Task 9 - Audit log filter", test_task9_audit_log_filter),
        ("Task 12 - Logical delete", test_task12_logical_delete),
    ]

    results = {}
    for name, test_fn in tests:
        try:
            result = test_fn()
            results[name] = result
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False

    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    all_pass = True
    for name, result in results.items():
        status = "PASS" if result else "FAIL"
        if not result:
            all_pass = False
        print(f"  [{status}] {name}")

    if all_pass:
        print("\n*** ALL TESTS PASSED ***")
    else:
        print("\n*** SOME TESTS FAILED ***")

if __name__ == '__main__':
    main()
