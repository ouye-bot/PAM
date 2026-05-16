import paramiko
import re
import os
import socket
import json as json_lib
import time as time_module
from datetime import datetime, timedelta
from app.utils.logger import get_logger

logger = get_logger('app.services.bypass_detector')

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'logs', 'bypass_detector.log')

def log(msg):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {msg}"
    logger.info(log_line)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_line + '\n')

from app.services.bypass_exemption import is_exempted

def get_proxy_egress_ip():
    proxy_ip = os.environ.get('PROXY_EGRESS_IP')
    if proxy_ip:
        log(f"[PROXY_EGRESS] 从环境变量 PROXY_EGRESS_IP 获取代理出口IP: {proxy_ip}")
        return proxy_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        log(f"[PROXY_EGRESS] 自动获取本机出口IP: {local_ip}")
        return local_ip
    except Exception:
        log(f"[PROXY_EGRESS] 获取出口IP失败，回退到 127.0.0.1")
        return '127.0.0.1'

def _get_auth_log_inode_size(ssh):
    try:
        stdin, stdout, stderr = ssh.exec_command(
            "stat -c '%i %s' /var/log/auth.log 2>/dev/null "
            "|| ls -li /var/log/auth.log 2>/dev/null | awk '{print $1, $6}' "
            "|| echo '0 0'"
        )
        output = stdout.read().decode('utf-8', errors='ignore').strip()
        parts = output.split()
        inode = int(parts[0]) if parts and parts[0].isdigit() else 0
        size_val = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return inode, size_val
    except Exception as e:
        log(f"[BYPASS] 获取auth.log文件元数据失败: {e}")
        return 0, 0

def _parse_last_bypass_meta(target_asset_str):
    from app.models import AuditLog
    try:
        last = AuditLog.query.filter(
            AuditLog.target_asset == target_asset_str,
            AuditLog.log_type.in_(['bypass_detected', 'bypass_check'])
        ).order_by(AuditLog.id.desc()).first()
        if not last:
            return 0, 0, 0
        detail = last.operation_detail or ''
        inode = 0
        offset = 0
        size_val = 0
        for part in detail.split('|'):
            if part.startswith('INODE:'):
                try: inode = int(part.split(':')[1])
                except: pass
            elif part.startswith('OFFSET:'):
                try: offset = int(part.split(':')[1])
                except: pass
            elif part.startswith('SIZE:'):
                try: size_val = int(part.split(':')[1])
                except: pass
        return inode, offset, size_val
    except Exception as e:
        log(f"[BYPASS] 解析上次审计日志元数据失败: {e}")
        return 0, 0, 0

def _build_detail_with_meta(detail_text, sm3_hash_val, inode, offset, size_val):
    parts = [detail_text]
    if sm3_hash_val:
        parts.append(f"SM3:{sm3_hash_val}")
    parts.append(f"INODE:{inode}|OFFSET:{offset}|SIZE:{size_val}")
    return '|'.join(parts)

def _write_bypass_audit_log(asset, bypassed, operation_detail):
    from app.services.audit_service import write_audit_log
    try:
        write_audit_log(
            log_type='bypass_detected' if bypassed else 'bypass_check',
            operator='system',
            source_ip='127.0.0.1',
            target_asset=f"{asset.ip}:{asset.ssh_port}",
            operation_detail=operation_detail,
            result='bypass' if bypassed else 'normal'
        )
    except Exception as e:
        log(f"[BYPASS] 写入审计日志失败: {e}")


def _detect_ssh_bypass(asset):
    if is_exempted(asset.id):
        log(f"[BYPASS] Asset {asset.id} 处于临时豁免期，跳过检测")
        return False, "资产处于临时豁免期"

    if asset.last_agent_login_time is None:
        log(f"[BYPASS DETECTOR] last_agent_login_time 为 NULL，首次登录豁免")
        return False, "首次登录豁免"

    log(f"{'='*60}")
    log(f"[BYPASS DETECTOR] 开始检测资产 ID={asset.id}, IP={asset.ip}, port={asset.ssh_port}")
    log(f"[BYPASS DETECTOR] Asset.last_agent_login_time = {asset.last_agent_login_time}")

    try:
        if not asset.credentials or len(asset.credentials) == 0:
            log(f"[BYPASS DETECTOR] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"

        credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
        if not credential:
            log(f"[BYPASS DETECTOR] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"
        log(f"[BYPASS DETECTOR] 使用凭证: {credential.account_name} (ID={credential.id})")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        host = asset.ip
        port = asset.ssh_port or 22
        username = credential.account_name

        from app.services.crypto_service import CryptoService
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            log(f"[BYPASS DETECTOR] 密码解密失败: asset_id={asset.id}")
            ssh.close()
            return False, "密码解密失败"
        log(f"[BYPASS DETECTOR] 密码解密成功")

        log(f"[BYPASS DETECTOR] 连接SSH: {host}:{port}")
        ssh.connect(host, port=port, username=username, password=password, timeout=10)
        log(f"[BYPASS DETECTOR] SSH连接成功")

        del password
        import gc
        gc.collect()

        target_asset_str = f"{asset.ip}:{asset.ssh_port}"
        last_inode, last_offset, last_size = _parse_last_bypass_meta(target_asset_str)
        current_inode, current_size = _get_auth_log_inode_size(ssh)

        log(f"[BYPASS DETECTOR] 文件元数据: inode={current_inode}, size={current_size} | "
            f"上次检测: inode={last_inode}, offset={last_offset}, size={last_size}")

        all_logins = []
        use_auth_log = True
        raw_source_text = ""
        detected_rotation = False
        sm3_hash_val = None
        offset_used = 0
        inode_used = current_inode
        size_used = current_size

        try:
            if current_inode == 0:
                log(f"[BYPASS DETECTOR] inode=0, 文件可能不存在，使用降级方案")
                raise Exception("auth.log not found (inode=0)")

            rotation_detected = False
            if last_offset > 0:
                if current_inode != last_inode:
                    rotation_detected = True
                    log(f"[BYPASS DETECTOR] 检测到日志轮转: inode {last_inode} -> {current_inode}")
                elif current_size < last_offset:
                    rotation_detected = True
                    log(f"[BYPASS DETECTOR] 检测到日志截断: SIZE={current_size} < OFFSET={last_offset}")

            if rotation_detected:
                detected_rotation = True
                log(f"[BYPASS DETECTOR] 尝试读取轮转文件补齐数据")
                rotation_content = b""
                try:
                    stdin, stdout, stderr = ssh.exec_command("cat /var/log/auth.log.1 2>/dev/null")
                    rotation_raw = stdout.read()
                    if rotation_raw and b"No such file or directory" not in rotation_raw:
                        rotation_content = rotation_raw
                        log(f"[BYPASS DETECTOR] 读取轮转文件成功: {len(rotation_content)}字节")
                except Exception as rot_e:
                    log(f"[BYPASS DETECTOR] 读取轮转文件失败: {rot_e}")

                stdin, stdout, stderr = ssh.exec_command("cat /var/log/auth.log")
                current_raw = stdout.read()
                combined_raw = rotation_content + current_raw
                raw_source_text = combined_raw.decode('utf-8', errors='ignore')
                offset_used = len(combined_raw)
                log(f"[BYPASS DETECTOR] 轮转后完整读取: {offset_used}字节")
            elif last_offset > 0:
                stdin, stdout, stderr = ssh.exec_command(f"tail -c +{last_offset + 1} /var/log/auth.log")
                raw_source_text = stdout.read().decode('utf-8', errors='ignore')
                offset_used = last_offset + len(raw_source_text.encode('utf-8'))
                log(f"[BYPASS DETECTOR] 增量读取: offset={last_offset}+1, 新增={len(raw_source_text)}字")
            else:
                stdin, stdout, stderr = ssh.exec_command("tail -n 300 /var/log/auth.log")
                raw_source_text = stdout.read().decode('utf-8', errors='ignore')
                offset_used = len(raw_source_text.encode('utf-8'))
                log(f"[BYPASS DETECTOR] 首次读取: {offset_used}字节")

            if not raw_source_text or "No such file or directory" in raw_source_text:
                raise Exception("auth.log not available")

            try:
                sm3_hash_val = CryptoService.sm3_hash(raw_source_text)
                log(f"[BYPASS DETECTOR] SM3哈希计算完成: {sm3_hash_val[:16]}...")
            except Exception as sm3_e:
                log(f"[BYPASS DETECTOR] SM3哈希计算失败: {sm3_e}")
                sm3_hash_val = "SM3_CALCULATION_FAILED"

            pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)'
            current_year = datetime.now().year

            for line in raw_source_text.split('\n'):
                line = line.strip()
                if not line:
                    continue

                match = re.search(pattern, line)
                if not match:
                    continue

                time_str = match.group(1)
                user = match.group(2)
                source_ip = match.group(3)

                try:
                    login_time = datetime.strptime(time_str, "%b %d %H:%M:%S")
                    login_time = login_time.replace(year=current_year)

                    if login_time > datetime.now():
                        login_time = login_time.replace(year=current_year - 1)
                        log(f"[BYPASS DETECTOR] 时间解析: 检测到未来时间，年份减1，解析后时间: {login_time}")

                    all_logins.append({
                        'time': login_time,
                        'user': user,
                        'source_ip': source_ip,
                        'raw_line': line
                    })
                    log(f"[BYPASS DETECTOR] 从auth.log解析: time={login_time}, user={user}, ip={source_ip}")
                except Exception as e:
                    log(f"[BYPASS DETECTOR] 解析auth.log时间失败: {e}")

            log(f"[BYPASS DETECTOR] 从auth.log解析完成，找到 {len(all_logins)} 条登录记录")

        except Exception as e:
            log(f"[BYPASS] auth.log unavailable, falling back to last -i: {str(e)}")
            use_auth_log = False

            log(f"[BYPASS DETECTOR] 降级到last -i获取登录记录")
            stdin, stdout, stderr = ssh.exec_command("last -i 2>/dev/null | head -n 100")
            last_output = stdout.read().decode('utf-8', errors='ignore')
            raw_source_text = last_output

            try:
                sm3_hash_val = CryptoService.sm3_hash(raw_source_text)
                log(f"[BYPASS DETECTOR] SM3哈希(last -i)计算完成: {sm3_hash_val[:16]}...")
            except Exception as sm3_e:
                log(f"[BYPASS DETECTOR] SM3哈希(last -i)计算失败: {sm3_e}")
                sm3_hash_val = "SM3_CALCULATION_FAILED"

            inode_used = 0
            offset_used = 0
            size_used = 0

            pattern = r'^(\S+)\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+(\w{3}\s+\d{1,2}\s+\d{2}:\d{2})'

            fetch_window = timedelta(hours=24)
            time_ago = datetime.now() - fetch_window

            for line in last_output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if 'wtmp' in line.lower() or 'boot' in line.lower():
                    continue

                match = re.match(pattern, line)
                if not match:
                    continue

                user = match.group(1)
                source_ip = match.group(2)
                time_str = match.group(3)

                try:
                    login_time = datetime.strptime(time_str, "%b %d %H:%M")
                    current_year = datetime.now().year
                    login_time = login_time.replace(year=current_year)

                    if login_time > datetime.now():
                        login_time = login_time.replace(year=current_year - 1)
                        log(f"[BYPASS DETECTOR] 时间解析: 检测到未来时间，年份减1，解析后时间: {login_time}")

                    if login_time > time_ago:
                        all_logins.append({
                            'time': login_time,
                            'user': user,
                            'source_ip': source_ip,
                            'raw_line': line
                        })
                        log(f"[BYPASS DETECTOR] 从last -i解析: time={login_time}, user={user}, ip={source_ip}")
                except Exception as e:
                    log(f"[BYPASS DETECTOR] 解析last -i时间失败: {e}")

            log(f"[BYPASS DETECTOR] 从last -i解析完成，找到 {len(all_logins)} 条登录记录（最近24小时内）")

        ssh.close()
        log(f"[BYPASS DETECTOR] SSH连接已关闭")

        if not all_logins:
            detail = _build_detail_with_meta(
                "未找到登录记录", sm3_hash_val,
                inode_used, offset_used, size_used
            )
            _write_bypass_audit_log(asset, False, detail)
            log(f"[BYPASS DETECTOR] Final Decision: bypass_detected=False, reason=未找到登录记录")
            return False, "未找到登录记录"

        TIME_TOLERANCE_SECONDS = 120
        last_login = asset.last_agent_login_time
        log(f"[BYPASS DETECTOR] 开始绕行判定，last_agent_login_time = {last_login}")

        for log_entry in all_logins:
            login_time = log_entry['time']

            if login_time > last_login:
                time_diff = abs((login_time - last_login).total_seconds())
                log(f"[BYPASS DETECTOR] 登录记录: time={login_time}, user={log_entry['user']}, ip={log_entry['source_ip']}")
                log(f"[BYPASS DETECTOR] 登录时间晚于last_agent_login_time，时间差: {time_diff}秒, 容差: {TIME_TOLERANCE_SECONDS}秒")

                if time_diff > TIME_TOLERANCE_SECONDS:
                    bypass_reason = f"检测到绕行登录：用户 {log_entry['user']} 从 {log_entry['source_ip']} 于 {login_time} 登录（与代理登录时间差 {int(time_diff)} 秒 > {TIME_TOLERANCE_SECONDS}秒）"
                    detail = _build_detail_with_meta(
                        bypass_reason, sm3_hash_val,
                        inode_used, offset_used, size_used
                    )
                    _write_bypass_audit_log(asset, True, detail)
                    log(f"[BYPASS DETECTOR] Final Decision: bypass_detected=True, reason={bypass_reason}")
                    return True, bypass_reason
                else:
                    log(f"[BYPASS DETECTOR] 判定: 忽略 - 时间差在容差范围内（可能是堡垒机自身登录）")
            else:
                log(f"[BYPASS DETECTOR] 登录记录: time={login_time}, user={log_entry['user']}, ip={log_entry['source_ip']} - 登录时间早于last_agent_login_time，跳过")

        detail = _build_detail_with_meta(
            "未检测到绕行登录", sm3_hash_val,
            inode_used, offset_used, size_used
        )
        _write_bypass_audit_log(asset, False, detail)
        log(f"[BYPASS DETECTOR] Final Decision: bypass_detected=False, reason=未检测到绕行登录")
        return False, "未检测到绕行登录"

    except Exception as e:
        log(f"[BYPASS DETECTOR] 检测失败: {str(e)}")
        return False, f"检测失败：{str(e)}"


def detect_windows_bypass(asset):
    if is_exempted(asset.id):
        log(f"[BYPASS WINDOWS] Asset {asset.id} 处于临时豁免期，跳过检测")
        return False, "资产处于临时豁免期"

    if asset.last_agent_login_time is None:
        log(f"[BYPASS WINDOWS] last_agent_login_time 为 NULL，首次登录豁免")
        return False, "首次登录豁免"

    log(f"{'='*60}")
    log(f"[BYPASS WINDOWS] 开始检测Windows资产 ID={asset.id}, IP={asset.ip}, port={asset.ssh_port}")
    log(f"[BYPASS WINDOWS] Asset.last_agent_login_time = {asset.last_agent_login_time}")

    try:
        if not asset.credentials or len(asset.credentials) == 0:
            log(f"[BYPASS WINDOWS] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"

        credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
        if not credential:
            log(f"[BYPASS WINDOWS] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"

        from app.services.crypto_service import CryptoService
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            log(f"[BYPASS WINDOWS] 密码解密失败: asset_id={asset.id}")
            return False, "密码解密失败"

        log(f"[BYPASS WINDOWS] 连接WinRM: {asset.ip}:{asset.ssh_port}")

        try:
            import winrm
            session = winrm.Session(
                f'http://{asset.ip}:{asset.ssh_port}/wsman',
                auth=(credential.account_name, password),
                transport='ntlm',
                operation_timeout_sec=15
            )
        except Exception as e:
            log(f"[BYPASS WINDOWS] WinRM连接失败: {e}")
            return False, f"WinRM连接失败: {str(e)}"
        finally:
            del password
            import gc
            gc.collect()

        target_machine_ts = None
        clock_delta = 0.0
        try:
            ts_result = session.run_ps('[DateTimeOffset]::Now.ToUnixTimeSeconds()')
            if ts_result.status_code == 0:
                target_ts_int = int(ts_result.std_out.decode('utf-8', errors='ignore').strip())
                pam_ts = time_module.time()
                clock_delta = pam_ts - target_ts_int
                target_machine_ts = datetime.fromtimestamp(target_ts_int)
                log(f"[BYPASS WINDOWS] 目标机当前时间戳: {target_ts_int}, PAM时间戳: {int(pam_ts)}, 时钟偏移Delta: {clock_delta:.1f}秒")

                if abs(clock_delta) > 300:
                    log(f"[BYPASS WINDOWS] 时钟漂移超过5分钟! Delta={clock_delta:.1f}秒")
                    _write_bypass_audit_log(asset, False,
                        f"TIME_DRIFT: PAM与目标机时钟偏差{int(clock_delta)}秒，超过300秒阈值|SM3:TIME_DRIFT|INODE:0|OFFSET:0|SIZE:0")
            else:
                log(f"[BYPASS WINDOWS] 获取目标机时间戳失败，跳过时钟漂移补偿")
        except Exception as e:
            log(f"[BYPASS WINDOWS] 获取目标机时间戳异常: {e}")

        try:
            log(f"[BYPASS WINDOWS] 查询安全日志清除事件(Event ID 1102)")
            last_check = asset.last_check_time
            if last_check:
                filter_date = last_check.strftime('%Y-%m-%dT%H:%M:%S')
                event1102_script = (
                    f"Get-WinEvent -FilterHashtable @{{LogName='Security'; ID=1102}} -MaxEvents 1 "
                    f"| Where-Object {{ $_.TimeCreated -gt [DateTime]'{filter_date}' }} "
                    f"| Select-Object TimeCreated | ConvertTo-Json"
                )
            else:
                event1102_script = (
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 1 "
                    "| Select-Object TimeCreated | ConvertTo-Json"
                )
            event1102_result = session.run_ps(event1102_script)
            if event1102_result.status_code == 0:
                raw_1102 = event1102_result.std_out.decode('utf-8', errors='ignore').strip()
                if raw_1102 and raw_1102 != 'null' and 'No events found' not in raw_1102:
                    try:
                        parsed_1102 = json_lib.loads(raw_1102)
                        if isinstance(parsed_1102, dict):
                            clear_time = parsed_1102.get('TimeCreated', 'unknown')
                        else:
                            clear_time = 'unknown'
                        sm3_1102 = CryptoService.sm3_hash(raw_1102)
                        log(f"[BYPASS WINDOWS] 检测到安全日志清除! TimeCreated={clear_time}")
                        from app.services.audit_service import write_audit_log
                        write_audit_log(
                            log_type='SECURITY_LOG_CLEARED',
                            operator='system',
                            source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail=f"检测到安全日志遭恶意清除，时间: {clear_time}|SM3:{sm3_1102}",
                            result='bypass'
                        )
                        return True, "安全日志遭清除"
                    except Exception as parse_e:
                        log(f"[BYPASS WINDOWS] 解析1102事件失败: {parse_e}")
        except Exception as e:
            log(f"[BYPASS WINDOWS] 查询安全日志清除事件失败: {e}")

        raw_json_text = ""
        use_wevtutil = False

        try:
            ps_script = (
                "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 100 "
                "| Where-Object { $_.Properties[8].Value -in @(2, 10) } "
                "| Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}} "
                "| ConvertTo-Json"
            )
            ps_result = session.run_ps(ps_script)
            raw_json_text = ps_result.std_out.decode('utf-8', errors='ignore') if ps_result.std_out else ''

            if not raw_json_text or 'No events found' in raw_json_text:
                log(f"[BYPASS WINDOWS] Get-WinEvent无返回，尝试wevtutil降级")
                use_wevtutil = True

        except Exception as e:
            log(f"[BYPASS WINDOWS] Get-WinEvent失败: {e}，尝试wevtutil降级")
            use_wevtutil = True

        if use_wevtutil:
            try:
                wevtutil_cmd = 'wevtutil qe Security "/q:*[System[(EventID=4624)]]" /c:100 /f:json'
                w_result = session.run_cmd(wevtutil_cmd)
                raw_json_text = w_result.std_out.decode('utf-8', errors='ignore') if w_result.std_out else ''
                if not raw_json_text:
                    log(f"[BYPASS WINDOWS] wevtutil降级也失败，安全日志不可用")
                    return False, "安全日志不可用"
            except Exception as e2:
                log(f"[BYPASS WINDOWS] wevtutil降级也失败: {e2}")
                return False, "安全日志不可用"

        sm3_hash_val = None
        try:
            sm3_hash_val = CryptoService.sm3_hash(raw_json_text)
            log(f"[BYPASS WINDOWS] SM3哈希计算完成: {sm3_hash_val[:16]}...")
        except Exception as sm3_e:
            log(f"[BYPASS WINDOWS] SM3哈希计算失败: {sm3_e}")
            sm3_hash_val = "SM3_CALCULATION_FAILED"

        all_logins = []
        try:
            parsed = json_lib.loads(raw_json_text)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for entry in parsed:
                user = entry.get('User', '') or ''
                source_ip = entry.get('SourceIP', '') or ''
                time_str = entry.get('TimeCreated', '')

                if user in ('SYSTEM', 'NETWORK SERVICE', 'LOCAL SERVICE', ''):
                    continue
                if source_ip == '127.0.0.1' or source_ip == '::1':
                    continue

                try:
                    if time_str.endswith('Z'):
                        time_str = time_str[:-1] + '+0000'
                    login_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S.%f%z')
                    login_time = login_time.replace(tzinfo=None)
                except Exception:
                    try:
                        login_time = datetime.strptime(time_str.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    except Exception:
                        log(f"[BYPASS WINDOWS] 解析时间失败: {time_str}")
                        continue

                if clock_delta != 0:
                    adjusted_time = login_time + timedelta(seconds=clock_delta)
                    log(f"[BYPASS WINDOWS] 时间补偿: 原始{login_time} + Delta{clock_delta:.1f}秒 = {adjusted_time}")
                    login_time = adjusted_time

                all_logins.append({
                    'time': login_time,
                    'user': user,
                    'source_ip': source_ip,
                    'raw': json_lib.dumps(entry)
                })
                log(f"[BYPASS WINDOWS] 解析安全日志: time={login_time}, user={user}, ip={source_ip}")

            log(f"[BYPASS WINDOWS] 解析完成，找到 {len(all_logins)} 条登录记录（LogonType 2/10）")
        except Exception as e:
            log(f"[BYPASS WINDOWS] 解析安全日志JSON失败: {e}")

        if not all_logins:
            detail = f"未找到Windows绕行登录记录|SM3:{sm3_hash_val}|INODE:0|OFFSET:0|SIZE:0"
            _write_bypass_audit_log(asset, False, detail)
            log(f"[BYPASS WINDOWS] Final Decision: bypass_detected=False, reason=未找到登录记录")
            return False, "未找到登录记录"

        TIME_TOLERANCE_SECONDS = 120
        last_login = asset.last_agent_login_time
        log(f"[BYPASS WINDOWS] 开始绕行判定，last_agent_login_time = {last_login}")

        for log_entry in all_logins:
            login_time = log_entry['time']

            if login_time > last_login:
                time_diff = abs((login_time - last_login).total_seconds())
                log(f"[BYPASS WINDOWS] 登录记录: time={login_time}, user={log_entry['user']}, ip={log_entry['source_ip']}")
                log(f"[BYPASS WINDOWS] 登录时间晚于last_agent_login_time，时间差: {time_diff}秒, 容差: {TIME_TOLERANCE_SECONDS}秒")

                if time_diff > TIME_TOLERANCE_SECONDS:
                    bypass_reason = f"检测到Windows绕行登录：用户 {log_entry['user']} 从 {log_entry['source_ip']} 于 {login_time} 登录（与代理登录时间差 {int(time_diff)} 秒 > {TIME_TOLERANCE_SECONDS}秒）"
                    detail = f"{bypass_reason}|SM3:{sm3_hash_val}|INODE:0|OFFSET:0|SIZE:0"
                    _write_bypass_audit_log(asset, True, detail)
                    log(f"[BYPASS WINDOWS] Final Decision: bypass_detected=True, reason={bypass_reason}")
                    return True, bypass_reason
                else:
                    log(f"[BYPASS WINDOWS] 判定: 忽略 - 时间差在容差范围内")
            else:
                log(f"[BYPASS WINDOWS] 登录记录: time={login_time}, user={log_entry['user']}, ip={log_entry['source_ip']} - 登录时间早于last_agent_login_time，跳过")

        detail = f"未检测到Windows绕行登录|SM3:{sm3_hash_val}|INODE:0|OFFSET:0|SIZE:0"
        _write_bypass_audit_log(asset, False, detail)
        log(f"[BYPASS WINDOWS] Final Decision: bypass_detected=False, reason=未检测到绕行登录")
        return False, "未检测到绕行登录"

    except Exception as e:
        log(f"[BYPASS WINDOWS] 检测失败: {str(e)}")
        return False, f"检测失败：{str(e)}"


def detect_bypass_for_mysql_asset(asset):
    if is_exempted(asset.id):
        log(f"[BYPASS MYSQL] Asset {asset.id} 处于临时豁免期，跳过检测")
        return False, "资产处于临时豁免期"

    log(f"{'='*60}")
    log(f"[BYPASS MYSQL] 开始检测MySQL资产 ID={asset.id}, IP={asset.ip}, port={asset.ssh_port}")

    try:
        if not asset.credentials or len(asset.credentials) == 0:
            log(f"[BYPASS MYSQL] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"

        credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
        if not credential:
            log(f"[BYPASS MYSQL] 资产 {asset.ip} 没有关联的凭证")
            return False, "资产没有关联的凭证"
        from app.services.crypto_service import CryptoService
        password = CryptoService.sm4_decrypt(credential.encrypted_password, credential.key_version)
        if password is None:
            log(f"[BYPASS MYSQL] 密码解密失败: asset_id={asset.id}")
            return False, "密码解密失败"

        import pymysql
        try:
            conn = pymysql.connect(
                host=asset.ip,
                port=asset.ssh_port or 3306,
                user=credential.account_name,
                password=password,
                connect_timeout=10
            )
            log(f"[BYPASS MYSQL] 连接MySQL成功: {asset.ip}:{asset.ssh_port}")
        finally:
            del password
            import gc
            gc.collect()

        proxy_egress = get_proxy_egress_ip()
        bypass_detected = False
        bypass_reason = ""

        cursor = conn.cursor()
        try:
            cursor.execute("SELECT ID, USER, HOST, DB, COMMAND, TIME FROM information_schema.processlist")
            rows = cursor.fetchall()
            log(f"[BYPASS MYSQL] information_schema.processlist 返回 {len(rows)} 条连接")
            use_info_schema = True
        except Exception as e:
            log(f"[BYPASS MYSQL] information_schema.processlist 不可用 ({str(e)})，降级到 SHOW PROCESSLIST")
            cursor.execute("SHOW PROCESSLIST")
            rows = cursor.fetchall()
            log(f"[BYPASS MYSQL] SHOW PROCESSLIST 返回 {len(rows)} 条连接")
            use_info_schema = False
        cursor.close()
        conn.close()

        system_users = {'event_scheduler', 'system user', 'root'}

        for row in rows:
            if use_info_schema:
                row_id = row[0]
                row_user = str(row[1] or '')
                row_host = str(row[2] or '')
                row_db = str(row[3] or '') if len(row) > 3 else ''
                row_command = str(row[4] or '') if len(row) > 4 else ''
                row_time = str(row[5] or '0') if len(row) > 5 else '0'
            else:
                row_id = row[0]
                row_user = str(row[1] if len(row) > 1 else '')
                row_host = str(row[2] if len(row) > 2 else '')
                row_db = str(row[3] if len(row) > 3 else '')
                row_command = str(row[4] if len(row) > 4 else '') if len(row) > 4 else ''
                row_time = str(row[5] if len(row) > 5 else '0') if len(row) > 5 else '0'

            if row_command == 'Sleep':
                continue
            if row_user in system_users:
                continue
            if ':' in row_host:
                source_ip = row_host.split(':')[0]
            else:
                source_ip = row_host
            if source_ip == proxy_egress:
                continue

            log(f"[BYPASS MYSQL] 发现绕行连接: user={row_user}, host={row_host}, db={row_db}, time={row_time}s")
            bypass_reason = f"检测到MySQL绕行连接：用户 {row_user} 从 {row_host} 连接数据库 {row_db}，已持续 {row_time} 秒"
            bypass_detected = True

            try:
                from app.services.audit_service import write_audit_log
                write_audit_log(
                    log_type='bypass_detected',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.name}({asset.ip}:{asset.ssh_port})",
                    operation_detail=bypass_reason,
                    result='bypass'
                )
            except Exception as audit_e:
                log(f"[BYPASS MYSQL] 写入审计日志失败: {audit_e}")

        if bypass_detected:
            log(f"[BYPASS MYSQL] Final Decision: bypass_detected=True")
            return True, bypass_reason

        log(f"[BYPASS MYSQL] 未发现绕行连接")
        log(f"[BYPASS MYSQL] Final Decision: bypass_detected=False, reason=未检测到绕行连接")
        return False, "未检测到绕行连接"

    except Exception as e:
        log(f"[BYPASS MYSQL] 检测失败: {str(e)}")
        return False, f"检测失败：{str(e)}"


def detect_bypass_for_asset(asset):
    from app.drivers import get_driver
    driver = get_driver(asset.os_type if hasattr(asset, 'os_type') and asset.os_type else None)
    return driver.detect_bypass(asset)


def check_auto_block_threshold(asset, source_ip):
    """
    检查是否达到自动阻断阈值

    从 system_config 读取策略配置（缺省：3次/24小时），
    查询该资产+来源IP最近时间窗内的绕行检测记录数。
    返回: (should_block: bool, recent_count: int, config: dict)
    """
    from app.models import SystemConfig, AuditLog
    from datetime import datetime, timedelta

    # 读取策略配置
    configs = SystemConfig.query.all()
    policy = {c.key: c.value for c in configs}

    enabled = policy.get('bypass_auto_block', 'true').lower() == 'true'
    if not enabled:
        return False, 0, {}

    threshold = int(policy.get('bypass_block_threshold', '3'))
    window_hours = int(policy.get('bypass_block_window', '24'))
    action = policy.get('bypass_block_action', 'rotate')

    target_asset_str = f"{asset.ip}:{asset.ssh_port}"
    cutoff = datetime.now() - timedelta(hours=window_hours)

    recent_count = AuditLog.query.filter(
        AuditLog.log_type == 'bypass_detected',
        AuditLog.target_asset == target_asset_str,
        AuditLog.source_ip == source_ip,
        AuditLog.timestamp >= cutoff
    ).count()

    should_block = recent_count >= threshold

    return should_block, recent_count, {
        'threshold': threshold,
        'window_hours': window_hours,
        'action': action,
        'enabled': enabled
    }