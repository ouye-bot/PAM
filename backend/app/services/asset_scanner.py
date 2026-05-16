import paramiko
import pymysql
import winrm
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from app.utils.logger import get_logger

logger = get_logger('app.services.asset_scanner')


def clean_hostname(hostname):
    if hostname is None:
        return ''
    if isinstance(hostname, bytes):
        hostname = hostname.decode('utf-8', errors='replace')
    else:
        hostname = str(hostname)
    safe = ''.join(c if c.isprintable() or c in '\n\r\t' else '?' for c in hostname)
    while '??' in safe:
        safe = safe.replace('??', '?')
    return safe.strip(' ?')[:200]


def scan_ssh(ip_str, port, username, passwords, discovered):
    for pwd in passwords:
        try:
            logger.info(f"[SCANNER]   Trying password: '{pwd[:2]}...'")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip_str, port=port, username=username, password=pwd, timeout=10)

            logger.info(f"[SCANNER]   Connected successfully to {ip_str}")

            _, stdout, _ = ssh.exec_command("cat /etc/os-release | grep PRETTY_NAME")
            os_info = stdout.read().decode(errors='replace').strip()
            os_type = "linux"
            if "Ubuntu" in os_info:
                os_type = "ubuntu"
            elif "CentOS" in os_info:
                os_type = "centos"
            elif "Debian" in os_info:
                os_type = "debian"

            _, stdout, _ = ssh.exec_command("hostname")
            hostname = clean_hostname(stdout.read())

            asset_info = {
                "ip": ip_str,
                "hostname": hostname,
                "os_type": os_type,
                "ssh_port": port,
                "account_name": username,
                "password": pwd
            }
            discovered.append(asset_info)
            logger.info(f"[SCANNER]   Added SSH asset: {ip_str} ({hostname})")
            ssh.close()
            break
        except Exception as e:
            logger.info(f"[SCANNER]   SSH failed: {str(e)[:80]}")
            continue


def scan_mysql(ip_str, port, username, passwords, discovered):
    for pwd in passwords:
        try:
            logger.info(f"[SCANNER]   Trying MySQL password: '{pwd[:2]}...'")
            conn = pymysql.connect(
                host=ip_str,
                port=port,
                user=username,
                password=pwd,
                connect_timeout=5,
                read_timeout=5,
                charset='utf8mb4'
            )
            logger.info(f"[SCANNER]   MySQL connected successfully to {ip_str}:{port}")

            cursor = conn.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            hostname = f"MySQL_{ip_str}"
            if version:
                display_name = clean_hostname(version[0])
                hostname = f"MySQL_{display_name.split('(')[0].strip()}"

            cursor.execute("SELECT @@hostname")
            hostname_row = cursor.fetchone()
            if hostname_row:
                raw = hostname_row[0]
                cleaned = clean_hostname(raw)
                if cleaned and cleaned.count('?') < len(cleaned) // 2:
                    hostname = cleaned

            cursor.close()
            conn.close()

            asset_info = {
                "ip": ip_str,
                "hostname": hostname,
                "os_type": "mysql",
                "ssh_port": port,
                "account_name": username,
                "password": pwd
            }
            discovered.append(asset_info)
            logger.info(f"[SCANNER]   Added MySQL asset: {ip_str}:{port} ({hostname})")
            break
        except Exception as e:
            logger.info(f"[SCANNER]   MySQL failed: {str(e)[:80]}")
            continue


def scan_winrm(ip_str, port, username, passwords, discovered):
    for pwd in passwords:
        try:
            logger.info(f"[SCANNER]   Trying WinRM password: '{pwd[:2]}...'")
            session = winrm.Session(
                f'http://{ip_str}:{port}/wsman',
                auth=(username, pwd),
                transport='ntlm',
                operation_timeout_sec=10
            )
            result = session.run_cmd('hostname')
            if result.status_code == 0:
                hostname = result.std_out.decode('utf-8', errors='ignore').strip()
                logger.info(f"[SCANNER]   WinRM connected successfully to {ip_str}:{port}")

                asset_info = {
                    "ip": ip_str,
                    "hostname": hostname or f"WIN_{ip_str}",
                    "os_type": "windows",
                    "ssh_port": port,
                    "account_name": username,
                    "password": pwd
                }
                discovered.append(asset_info)
                logger.info(f"[SCANNER]   Added Windows asset: {ip_str} ({hostname})")
                break
            else:
                err_msg = result.std_err.decode('utf-8', errors='ignore')[:80]
                logger.info(f"[SCANNER]   WinRM cmd failed: {err_msg}")
        except winrm.exceptions.AuthenticationError:
            logger.info(f"[SCANNER]   WinRM auth failed: {ip_str}")
        except Exception as e:
            logger.info(f"[SCANNER]   WinRM failed: {str(e)[:80]}")
            continue


def scan_network(ip_range: str, port: int = 22, username: str = 'root', passwords: list = None, scan_type: str = 'ssh', existing_assets: list = None):
    """扫描指定 IP 范围，返回发现的资产列表"""
    if passwords is None:
        passwords = ['123456', 'root', 'admin', '123456']

    discovered = []
    ips_to_scan = []

    existing_keys = set()
    if existing_assets:
        for a in existing_assets:
            ip = a.get('ip') or a.get('host') or ''
            p = a.get('ssh_port') or a.get('port') or 0
            existing_keys.add(f"{ip}:{p}")

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        ips_to_scan = [str(ip) for ip in network.hosts()]
        logger.info(f"[SCANNER] Scanning network: {ip_range}, found {len(ips_to_scan)} hosts")
    except ValueError:
        ips_to_scan = [ip_range]
        logger.info(f"[SCANNER] Scanning single host: {ip_range}")

    def scan_ip(ip):
        ip_str = ip
        key = f"{ip_str}:{port}"
        if key in existing_keys:
            logger.info(f"[SCANNER] Skipping {key} (already exists)")
            return
        logger.info(f"[SCANNER] Scanning {ip_str}:{port} (type={scan_type})")
        if scan_type == 'mysql':
            scan_mysql(ip_str, port, username, passwords, discovered)
        elif scan_type == 'windows':
            scan_winrm(ip_str, port, username, passwords, discovered)
        else:
            scan_ssh(ip_str, port, username, passwords, discovered)

    logger.info(f"[SCANNER] Starting scan of {len(ips_to_scan)} targets...")

    for ip in ips_to_scan:
        scan_ip(ip)

    logger.info(f"[SCANNER] Scan completed. Discovered {len(discovered)} assets")
    return discovered