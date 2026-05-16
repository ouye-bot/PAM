import os,sys,requests,time

BASE_URL = 'http://127.0.0.1:5000'
test_results = []

def report(name, status, detail=''):
    result = 'PASS' if status else 'FAIL'
    test_results.append((name, result, detail))
    print(f'  [{result}] {name}')
    if detail: print(f'         {detail}')

s = requests.Session()
print('='*60)
print('P2-R3 SM3完整性校验 验证测试')
print('='*60)

print('\n--- 登录获取Token ---')
resp = s.post(f'{BASE_URL}/api/auth/login', json={'username':'admin','password':'admin123'})
report('登录成功', resp.status_code==200)
token = resp.json().get('token','')
headers = {'Authorization': f'Bearer {token}'}

print('\n--- 触发绕行检测（通过API） ---')
resp = s.post(f'{BASE_URL}/api/bypass/trigger', headers=headers)
report('绕行检测API调用成功', resp.status_code==200, f'status={resp.status_code}')
if resp.status_code==200:
    data = resp.json()
    print(f'  响应: {data}')

print('\n--- 检查审计日志是否包含SM3 ---')
time.sleep(2)

# Get latest bypass audit logs
resp = s.get(f'{BASE_URL}/api/sessions', headers=headers)
# Actually, let me directly query audit logs via API
resp = s.get(f'{BASE_URL}/api/audit/logs?page=1&page_size=20', headers=headers)
if resp.status_code==200:
    data = resp.json()
    audit_data = data.get('data',{})
    items = audit_data.get('items',[]) if isinstance(audit_data,dict) else []
    if items:
        bypass_logs = [log for log in items if '绕行' in str(log.get('operation_detail','')) or 'bypass' in str(log.get('log_type',''))]
        report(f'审计日志查询成功，共{len(items)}条', True)
        if bypass_logs:
            latest = bypass_logs[0]
            detail = latest.get('operation_detail','')
            log_type = latest.get('log_type','')
            print(f'  最新绕行检测日志: type={log_type}')
            print(f'  operation_detail: {detail[:200]}')
            
            has_sm3 = 'SM3:' in detail
            has_inode = 'INODE:' in detail
            has_offset = 'OFFSET:' in detail
            has_size = 'SIZE:' in detail
            
            report(f'审计日志包含SM3哈希', has_sm3, detail[:100] if has_sm3 else '未找到SM3:字段')
            report(f'审计日志包含INODE', has_inode)
            report(f'审计日志包含OFFSET', has_offset)
            report(f'审计日志包含SIZE', has_size)
            
            if has_sm3:
                sm3_part = [p for p in detail.split('|') if p.startswith('SM3:')]
                if sm3_part:
                    hash_val = sm3_part[0].split(':')[1]
                    report(f'SM3哈希值格式正确', len(hash_val)==64, f'{hash_val[:16]}...{hash_val[-16:]} ({len(hash_val)}字符)')
                    report(f'SM3哈希不为SM3_CALCULATION_FAILED', hash_val != 'SM3_CALCULATION_FAILED')
        else:
            report('审计日志中有绕行检查记录', False, f'未找到绕行相关日志（共{len(items)}条）')
            if items:
                print(f'  最新日志: type={items[0].get("log_type","")}, type={items[0].get("log_type","")}')
    else:
        report('审计日志列表不为空', len(items)>0, f'items为空')
else:
    report(f'审计日志查询API', resp.status_code==200, f'status={resp.status_code}')

print('\n--- 检查bypass_detector.log ---')
log_path = os.path.join(os.path.dirname(__file__),'logs','bypass_detector.log')
if os.path.exists(log_path):
    with open(log_path,'r',encoding='utf-8',errors='ignore') as f:
        lines = f.readlines()
    sm3_lines = [l for l in lines if 'SM3' in l]
    inode_lines = [l for l in lines if '文件元数据' in l]
    report(f'日志文件存在且有{len(lines)}行', True)
    report(f'日志中包含SM3相关行', len(sm3_lines)>0, f'{len(sm3_lines)}行')
    report(f'日志中包含inode/offset', len(inode_lines)>0)
    if inode_lines:
        print(f'  最新inode行: {inode_lines[-1].strip()}')
else:
    report(f'bypass_detector.log存在', False)

print('\n' + '='*60)
print('测试汇总')
print('='*60)
passed = sum(1 for r in test_results if r[1]=='PASS')
failed = sum(1 for r in test_results if r[1]=='FAIL')
print(f'通过: {passed}, 失败: {failed}, 总计: {len(test_results)}')
for name,result,detail in test_results:
    status_str='OK' if result=='PASS' else 'XX'
    print(f'  [{status_str}] {name}')
    if detail: print(f'         {detail}')
if failed>0:
    print('\n存在失败测试！')
    sys.exit(1)
else:
    print('\n所有测试通过！')