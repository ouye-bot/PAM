from flask_apscheduler import APScheduler
from app.models import Asset
from app.services.audit_service import write_audit_log, auto_lock_old_logs
from app.services.password_rotation import rotate_password
from app.services.bypass_detector import detect_bypass_for_asset
import paramiko
import pymysql
import socket
import json
import uuid
from datetime import datetime
from app.utils.logger import get_logger

logger = get_logger('app.scheduler')

scheduler = APScheduler()

_scheduler_app = None

SCHEDULES_CONFIG_KEY = 'rotation_schedules'

# Default schedules when none are configured
DEFAULT_SCHEDULES = [
    {
        "id": "default-ssh",
        "name": "每日SSH资产改密",
        "asset_ids": [],
        "asset_types": ["ubuntu", "debian", "centos", "rhel", "linux"],
        "cron": "0 2 * * *",
        "enabled": True,
        "created_at": ""
    },
    {
        "id": "default-mysql",
        "name": "MySQL资产定时改密",
        "asset_ids": [],
        "asset_types": ["mysql"],
        "cron": "*/30 * * * *",
        "enabled": True,
        "created_at": ""
    }
]


def _get_schedules_from_db():
    """从system_config表读取调度配置"""
    if _scheduler_app is None:
        return []
    with _scheduler_app.app_context():
        from app.models import SystemConfig
        config = SystemConfig.query.filter_by(key=SCHEDULES_CONFIG_KEY).first()
        if config and config.value:
            try:
                return json.loads(config.value)
            except (json.JSONDecodeError, TypeError):
                logger.error("[调度器] 调度配置JSON解析失败，使用默认配置")
        return None


def _save_schedules_to_db(schedules):
    """保存调度配置到system_config表"""
    if _scheduler_app is None:
        return
    with _scheduler_app.app_context():
        from app.models import SystemConfig
        from app import db
        config = SystemConfig.query.filter_by(key=SCHEDULES_CONFIG_KEY).first()
        if config:
            config.value = json.dumps(schedules, ensure_ascii=False)
        else:
            config = SystemConfig(key=SCHEDULES_CONFIG_KEY, value=json.dumps(schedules, ensure_ascii=False))
            db.session.add(config)
        db.session.commit()


def _run_schedule_job(schedule):
    """执行单个调度任务：匹配资产并依次改密"""
    if _scheduler_app is None:
        return
    with _scheduler_app.app_context():
        from app import db
        # 按资产ID或类型匹配
        if schedule.get('asset_ids'):
            assets = Asset.query.filter(
                Asset.status == 'active',
                Asset.id.in_(schedule['asset_ids'])
            ).all()
        elif schedule.get('asset_types'):
            assets = Asset.query.filter(
                Asset.status == 'active',
                Asset.os_type.in_(schedule['asset_types'])
            ).all()
        else:
            assets = Asset.query.filter_by(status='active').all()

        if not assets:
            logger.info(f"[调度任务] {schedule['name']}: 无匹配资产")
            return

        logger.info(f"[调度任务] {schedule['name']}: 匹配到 {len(assets)} 个资产")
        success_count = 0
        failed_count = 0

        for asset in assets:
            try:
                logger.info(f"[调度任务] 正在为资产 {asset.ip}:{asset.ssh_port} 执行改密...")
                rotate_password(asset.id)
                success_count += 1
                logger.info(f"[调度任务] 资产 {asset.ip} 改密成功")
            except Exception as e:
                failed_count += 1
                logger.error(f"[调度任务] 资产 {asset.ip} 改密失败: {str(e)}", exc_info=True)

        logger.info(f"[调度任务] {schedule['name']}: 完成，成功 {success_count}，失败 {failed_count}")

        try:
            write_audit_log(
                log_type='system_notice',
                operation_detail=f"定时改密[{schedule['name']}]完成，成功 {success_count} 台，失败 {failed_count} 台",
                operator='system',
                source_ip='127.0.0.1',
                target_asset='system'
            )
        except Exception as e:
            logger.error(f"[调度任务] 写入审计日志失败: {str(e)}")


def apply_schedule_jobs():
    """从数据库加载调度配置并动态注册/更新APScheduler任务"""
    schedules = _get_schedules_from_db()
    if schedules is None:
        schedules = DEFAULT_SCHEDULES
        _save_schedules_to_db(schedules)
        logger.info("[调度器] 初始化默认调度配置")

    # 移除所有rotation_schedule_前缀的任务
    existing_jobs = [j for j in scheduler.get_jobs() if j.id.startswith('rotation_schedule_')]
    for job in existing_jobs:
        scheduler.remove_job(job.id)
        logger.info(f"[调度器] 移除旧调度任务: {job.id}")

    # 注册启用的调度
    from apscheduler.triggers.cron import CronTrigger

    for sched in schedules:
        if not sched.get('enabled', True):
            continue
        job_id = f"rotation_schedule_{sched['id']}"
        try:
            parts = sched['cron'].strip().split()
            scheduler.add_job(
                id=job_id,
                func=_run_schedule_job,
                args=(sched,),
                trigger=CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                ),
                replace_existing=True
            )
            logger.info(f"[调度器] 注册调度任务: {sched['name']} (cron={sched['cron']})")
        except Exception as e:
            logger.error(f"[调度器] 注册调度任务失败 [{sched['name']}]: {str(e)}")


def get_all_schedules():
    """获取所有调度配置"""
    schedules = _get_schedules_from_db()
    if schedules is None:
        schedules = DEFAULT_SCHEDULES
    return schedules


def add_schedule(name, asset_ids, asset_types, cron, enabled=True):
    """新增调度配置并即时生效"""
    schedules = _get_schedules_from_db()
    if schedules is None:
        schedules = []

    new_sched = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "asset_ids": asset_ids or [],
        "asset_types": asset_types or [],
        "cron": cron,
        "enabled": enabled,
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    schedules.append(new_sched)
    _save_schedules_to_db(schedules)
    apply_schedule_jobs()
    return new_sched


def update_schedule(schedule_id, updates):
    """更新调度配置并即时生效"""
    schedules = _get_schedules_from_db()
    if schedules is None:
        return None
    for sched in schedules:
        if sched['id'] == schedule_id:
            for key in ('name', 'asset_ids', 'asset_types', 'cron', 'enabled'):
                if key in updates:
                    sched[key] = updates[key]
            _save_schedules_to_db(schedules)
            apply_schedule_jobs()
            return sched
    return None


def delete_schedule(schedule_id):
    """删除调度配置并即时生效"""
    schedules = _get_schedules_from_db()
    if schedules is None:
        return False
    new_schedules = [s for s in schedules if s['id'] != schedule_id]
    if len(new_schedules) == len(schedules):
        return False
    _save_schedules_to_db(new_schedules)
    apply_schedule_jobs()
    return True


def scan_pending_passwords():
    """
    系统启动时扫描所有带pending_password的凭据，尝试容灾恢复
    分别用正式密码和pending密码尝试连接，连通哪个就以哪个为准
    """
    global _scheduler_app
    if _scheduler_app is None:
        logger.error("[调度器] Flask app not initialized in scheduler")
        return
    with _scheduler_app.app_context():
        from app import db
        from app.models import Credential, Asset
        from app.services.crypto_service import CryptoService

        pending_creds = Credential.query.filter(Credential.pending_password.isnot(None)).all()
        if not pending_creds:
            logger.info("[容灾恢复] 未发现待恢复的pending_password凭据")
            return

        logger.info(f"[容灾恢复] 发现 {len(pending_creds)} 个待恢复的pending_password凭据")

        for cred in pending_creds:
            asset = Asset.query.get(cred.asset_id)
            if not asset:
                logger.error(f"[容灾恢复] Credential {cred.id} 关联的Asset不存在")
                continue

            logger.info(f"[容灾恢复] 尝试恢复 Asset {asset.ip}:{asset.ssh_port}, credential_id={cred.id}")

            official_password = CryptoService.sm4_decrypt(cred.encrypted_password, cred.key_version)
            pending_password = CryptoService.sm4_decrypt(cred.pending_password, cred.pending_key_version)

            if official_password is None and pending_password is None:
                logger.error(f"[容灾恢复] 双密码解密均失败: credential_id={cred.id}")
                write_audit_log(
                    log_type='system_notice',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f'容灾恢复失败: pending_password和正式密码均解密失败, credential_id={cred.id}',
                    result='failed'
                )
                del official_password, pending_password
                import gc; gc.collect()
                continue

            if asset.os_type and asset.os_type.lower() == 'windows':
                if asset.account_type == 'domain':
                    logger.warning(f"[容灾恢复] 跳过域账号 pending_password 恢复: {cred.account_name}")
                    write_audit_log(
                        log_type='system_notice',
                        operator='system',
                        source_ip='127.0.0.1',
                        target_asset=f"{asset.ip}:{asset.ssh_port}",
                        operation_detail=f'容灾恢复跳过(域账号): {cred.account_name}，清理pending_password',
                        result='skipped'
                    )
                    cred.pending_password = None
                    cred.pending_key_version = None
                    db.session.commit()
                    del official_password, pending_password
                    import gc; gc.collect()
                    continue
                import winrm
                if pending_password:
                    try:
                        ps = winrm.Session(
                            f'http://{asset.ip}:{asset.ssh_port}/wsman',
                            auth=(cred.account_name, pending_password),
                            transport='ntlm',
                            operation_timeout_sec=10
                        )
                        r = ps.run_cmd('echo ok')
                        if r.status_code == 0:
                            logger.info(f"[容灾恢复] pending_password可用，晋升为正式密码: credential_id={cred.id}")
                            cred.encrypted_password = cred.pending_password
                            cred.key_version = cred.pending_key_version
                            cred.pending_password = None
                            cred.pending_key_version = None
                            db.session.commit()
                            write_audit_log(
                                log_type='system_notice',
                                operator='system',
                                source_ip='127.0.0.1',
                                target_asset=f"{asset.ip}:{asset.ssh_port}",
                                operation_detail='容灾恢复成功: pending_password晋升为正式密码',
                                result='success'
                            )
                            del official_password, pending_password
                            import gc; gc.collect()
                            continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] pending_password不可用: {e}")
                if official_password:
                    try:
                        os = winrm.Session(
                            f'http://{asset.ip}:{asset.ssh_port}/wsman',
                            auth=(cred.account_name, official_password),
                            transport='ntlm',
                            operation_timeout_sec=10
                        )
                        r = os.run_cmd('echo ok')
                        if r.status_code == 0:
                            logger.info(f"[容灾恢复] 正式密码仍然可用，清除pending_password: credential_id={cred.id}")
                            cred.pending_password = None
                            cred.pending_key_version = None
                            db.session.commit()
                            write_audit_log(
                                log_type='system_notice',
                                operator='system',
                                source_ip='127.0.0.1',
                                target_asset=f"{asset.ip}:{asset.ssh_port}",
                                operation_detail='容灾恢复: 正式密码可用，清除pending_password',
                                result='success'
                            )
                            del official_password, pending_password
                            import gc; gc.collect()
                            continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] 正式密码也不可用: {e}")
                logger.error(f"[容灾恢复] CRITICAL: 双密码均不可用，保留pending_password: credential_id={cred.id}")
                write_audit_log(
                    log_type='system_notice',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f'容灾恢复失败: pending_password和正式密码均不可用, credential_id={cred.id}',
                    result='failed'
                )
            elif asset.os_type and asset.os_type.lower() == 'mysql':
                import pymysql
                if pending_password:
                    try:
                        mc = pymysql.connect(
                            host=asset.ip, port=asset.ssh_port or 3306,
                            user=cred.account_name, password=pending_password,
                            connect_timeout=10, read_timeout=10
                        )
                        mc.close()
                        logger.info(f"[容灾恢复] pending_password可用(MySQL)，晋升为正式密码: credential_id={cred.id}")
                        cred.encrypted_password = cred.pending_password
                        cred.key_version = cred.pending_key_version
                        cred.pending_password = None
                        cred.pending_key_version = None
                        db.session.commit()
                        write_audit_log(
                            log_type='system_notice',
                            operator='system',
                            source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail='容灾恢复成功(MySQL): pending_password晋升为正式密码',
                            result='success'
                        )
                        del official_password, pending_password
                        import gc; gc.collect()
                        continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] pending_password不可用(MySQL): {e}")
                if official_password:
                    try:
                        mc = pymysql.connect(
                            host=asset.ip, port=asset.ssh_port or 3306,
                            user=cred.account_name, password=official_password,
                            connect_timeout=10, read_timeout=10
                        )
                        mc.close()
                        logger.info(f"[容灾恢复] 正式密码仍然可用(MySQL)，清除pending_password: credential_id={cred.id}")
                        cred.pending_password = None
                        cred.pending_key_version = None
                        db.session.commit()
                        write_audit_log(
                            log_type='system_notice',
                            operator='system',
                            source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail='容灾恢复(MySQL): 正式密码可用，清除pending_password',
                            result='success'
                        )
                        del official_password, pending_password
                        import gc; gc.collect()
                        continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] 正式密码也不可用(MySQL): {e}")
                logger.error(f"[容灾恢复] CRITICAL: 双密码均不可用(MySQL)，保留pending_password: credential_id={cred.id}")
                write_audit_log(
                    log_type='system_notice',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f'容灾恢复失败(MySQL): pending_password和正式密码均不可用, credential_id={cred.id}',
                    result='failed'
                )

            else:
                if pending_password:
                    try:
                        import paramiko
                        pc = paramiko.SSHClient()
                        pc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        pc.connect(hostname=asset.ip, port=asset.ssh_port or 22,
                                   username=cred.account_name, password=pending_password, timeout=10)
                        pc.close()
                        logger.info(f"[容灾恢复] pending_password可用(SSH)，晋升为正式密码: credential_id={cred.id}")
                        cred.encrypted_password = cred.pending_password
                        cred.key_version = cred.pending_key_version
                        cred.pending_password = None
                        cred.pending_key_version = None
                        db.session.commit()
                        write_audit_log(
                            log_type='system_notice',
                            operator='system',
                            source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail='容灾恢复成功(SSH): pending_password晋升为正式密码',
                            result='success'
                        )
                        del official_password, pending_password
                        import gc; gc.collect()
                        continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] pending_password不可用(SSH): {e}")
                if official_password:
                    try:
                        import paramiko
                        oc = paramiko.SSHClient()
                        oc.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        oc.connect(hostname=asset.ip, port=asset.ssh_port or 22,
                                   username=cred.account_name, password=official_password, timeout=10)
                        oc.close()
                        logger.info(f"[容灾恢复] 正式密码仍然可用(SSH)，清除pending_password: credential_id={cred.id}")
                        cred.pending_password = None
                        cred.pending_key_version = None
                        db.session.commit()
                        write_audit_log(
                            log_type='system_notice',
                            operator='system',
                            source_ip='127.0.0.1',
                            target_asset=f"{asset.ip}:{asset.ssh_port}",
                            operation_detail='容灾恢复(SSH): 正式密码可用，清除pending_password',
                            result='success'
                        )
                        del official_password, pending_password
                        import gc; gc.collect()
                        continue
                    except Exception as e:
                        logger.info(f"[容灾恢复] 正式密码也不可用(SSH): {e}")
                logger.error(f"[容灾恢复] CRITICAL: 双密码均不可用(SSH)，保留pending_password: credential_id={cred.id}")
                write_audit_log(
                    log_type='system_notice',
                    operator='system',
                    source_ip='127.0.0.1',
                    target_asset=f"{asset.ip}:{asset.ssh_port}",
                    operation_detail=f'容灾恢复失败(SSH): pending_password和正式密码均不可用, credential_id={cred.id}',
                    result='failed'
                )

            del official_password, pending_password
            import gc
            gc.collect()

def check_assets_connectivity():
    """
    定时检查资产连通性
    """
    global _scheduler_app
    if _scheduler_app is None:
        logger.error("[调度器] Flask app not initialized in scheduler")
        return
    logger.info("[巡检] 任务开始执行")
    logger.info("开始执行资产连通性检测...")

    online_count = 0
    offline_count = 0
    error_count = 0

    with _scheduler_app.app_context():
        active_assets = Asset.query.filter_by(status='active').all()
        logger.info(f"发现 {len(active_assets)} 个活跃资产")

        for asset in active_assets:
            try:
                is_online = check_asset_connectivity(asset)
                if is_online:
                    asset.connectivity = 'online'
                    online_count += 1
                    logger.info(f"资产 {asset.ip} 在线")
                else:
                    asset.connectivity = 'offline'
                    offline_count += 1
                    logger.info(f"资产 {asset.ip} 离线")
                asset.last_check_time = datetime.now()
            except Exception as e:
                asset.connectivity = 'unknown'
                error_count += 1
                logger.error(f"资产 {asset.ip} 检测异常: {str(e)}", exc_info=True)
                asset.last_check_time = datetime.now()
                continue

        from app import db
        db.session.commit()
        logger.info(f"资产连通性检测完成，在线 {online_count}，离线 {offline_count}，异常 {error_count}")

def check_asset_connectivity(asset):
    """检查单个资产的连通性（委托给资产驱动）"""
    try:
        if not asset.credentials:
            logger.info(f"资产 {asset.ip} 无关联凭证，跳过")
            return False
        credential = max(asset.credentials, key=lambda c: c.id) if asset.credentials else None
        from app.drivers import get_driver
        driver = get_driver(asset.os_type)
        result = driver.check_connectivity(asset, credential)
        return result.get('success', False)
    except Exception as e:
        logger.error(f"资产 {asset.ip} 检测失败: {str(e)}", exc_info=True)
        return False

def detect_bypass_login():
    """
    定时执行绕行登录检测任务（含自动阻断）
    """
    global _scheduler_app
    if _scheduler_app is None:
        logger.error("[调度器] Flask app not initialized in scheduler")
        return
    logger.info("开始执行绕行登录检测任务...")

    with _scheduler_app.app_context():
        from app.services.bypass_detector import check_auto_block_threshold
        from app.services.password_rotation import rotate_password
        from app.services.audit_service import write_audit_log

        active_assets = Asset.query.filter_by(status='active').all()
        logger.info(f"发现 {len(active_assets)} 个活跃资产")

        total_detected = 0
        total_blocked = 0

        for asset in active_assets:
            try:
                logger.info(f"正在检测资产 {asset.ip} 的绕行登录...")
                bypassed, detail = detect_bypass_for_asset(asset)
                if bypassed:
                    total_detected += 1
                    logger.info(f"资产 {asset.ip} 检测到绕行登录: {detail}")

                    # 提取来源IP（从detail中解析）
                    import re
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', detail)
                    source_ip = ip_match.group(0) if ip_match else 'unknown'

                    # 检查自动阻断阈值
                    should_block, count, config = check_auto_block_threshold(asset, source_ip)
                    if should_block:
                        logger.warning(
                            f"[自动阻断] 资产 {asset.ip}:{asset.ssh_port} "
                            f"来源IP {source_ip} 在过去{config['window_hours']}小时内"
                            f"绕行{count}次（阈值{config['threshold']}次），触发自动阻断"
                        )
                        try:
                            rotate_password(asset.id)
                            total_blocked += 1
                            write_audit_log(
                                'bypass_auto_block',
                                operator='system',
                                source_ip=source_ip,
                                target_asset=f"{asset.ip}:{asset.ssh_port}",
                                operation_detail=(
                                    f'[自动阻断] 检测到来源IP {source_ip} '
                                    f'在{config["window_hours"]}小时内绕行{count}次（阈值{config["threshold"]}次），'
                                    f'已自动触发密码轮换'
                                ),
                                result='success'
                            )
                            logger.info(f"[自动阻断] 资产 {asset.ip} 改密成功")
                        except Exception as rotate_err:
                            logger.error(f"[自动阻断] 资产 {asset.ip} 改密失败: {str(rotate_err)}")
                            write_audit_log(
                                'bypass_auto_block',
                                operator='system',
                                source_ip=source_ip,
                                target_asset=f"{asset.ip}:{asset.ssh_port}",
                                operation_detail=(
                                    f'[自动阻断失败] 绕行检测触发自动改密失败: {str(rotate_err)}'
                                ),
                                result='failed'
                            )
                else:
                    logger.info(f"资产 {asset.ip} 未检测到绕行登录")
            except Exception as e:
                logger.error(f"资产 {asset.ip} 绕行检测失败: {str(e)}", exc_info=True)
                continue

        logger.info(
            f"绕行登录检测任务执行完成 — "
            f"检测到绕行: {total_detected} 次, 自动阻断: {total_blocked} 次"
        )


def _progressive_re_encrypt():
    """密钥平滑轮换：每次执行迁移一批凭证（10条）"""
    with _scheduler_app.app_context():
        from app import db
        from app.models import KeyVersion, Credential
        from app.services.crypto_service import CryptoService

        rotating_key = KeyVersion.query.filter_by(status='rotating').first()
        if not rotating_key:
            return

        old_key = KeyVersion.query.filter_by(status='active').first()
        if not old_key:
            rotating_key.status = 'active'
            db.session.commit()
            logger.info("[KEY-ROTATION] 无旧active密钥，rotating密钥直接提升为active: id=%s", rotating_key.id)
            return

        try:
            old_work_key = CryptoService.decrypt_work_key(old_key.encrypted_key)
        except Exception:
            old_work_key = None

        if old_work_key is None:
            logger.error("[KEY-ROTATION] 无法解密旧工作密钥，跳过此轮: old_key_id=%s", old_key.id)
            rotating_key.status = 'active'
            old_key.status = 'retired'
            db.session.commit()
            return

        new_work_key = CryptoService.decrypt_work_key(rotating_key.encrypted_key)
        if new_work_key is None:
            logger.error("[KEY-ROTATION] 无法解密新工作密钥，跳过此轮: new_key_id=%s", rotating_key.id)
            return

        batch_size = 10
        remaining = Credential.query.filter(Credential.key_version != rotating_key.id).limit(batch_size).all()

        if not remaining:
            old_key.status = 'retired'
            rotating_key.status = 'active'
            db.session.commit()
            write_audit_log(
                log_type='key_rotation',
                operator='system',
                source_ip='127.0.0.1',
                target_asset='System',
                operation_detail=f'密钥轮换完成：旧密钥ID {old_key.id} retired，新密钥ID {rotating_key.id} active',
                result='success'
            )
            logger.info("[KEY-ROTATION] 全部凭证迁移完成: new_key_id=%s active, old_key_id=%s retired",
                        rotating_key.id, old_key.id)
            return

        migrated = 0
        failed = 0
        for cred in remaining:
            try:
                password = CryptoService.decrypt_with_work_key(cred.encrypted_password, old_work_key)
                if password is None:
                    failed += 1
                    continue
                cred.encrypted_password = CryptoService.encrypt_with_work_key(password, new_work_key)
                cred.key_version = rotating_key.id

                if cred.pending_password:
                    pending_pwd = CryptoService.decrypt_with_work_key(cred.pending_password, old_work_key)
                    if pending_pwd is not None:
                        cred.pending_password = CryptoService.encrypt_with_work_key(pending_pwd, new_work_key)
                        cred.pending_key_version = rotating_key.id
                migrated += 1
            except Exception as e:
                logger.error("[KEY-ROTATION] 迁移凭证失败: cred_id=%s, %s", cred.id, e)
                failed += 1

        db.session.commit()

        total = Credential.query.count()
        done = Credential.query.filter_by(key_version=rotating_key.id).count()
        logger.info("[KEY-ROTATION] 批次完成: migrated=%d, failed=%d, progress=%d/%d", migrated, failed, done, total)


# === T4: Pause/resume rotation jobs during key re-encryption ===

_paused_rotation_jobs = []

def pause_rotation_jobs():
    """Pause all rotation_schedule_ jobs during key re-encryption."""
    global _paused_rotation_jobs
    _paused_rotation_jobs = []
    for job in scheduler.get_jobs():
        if job.id.startswith('rotation_schedule_'):
            scheduler.pause_job(job.id)
            _paused_rotation_jobs.append(job.id)
    logger.info("[SCHEDULER] Paused %d rotation jobs for re-encryption", len(_paused_rotation_jobs))


def resume_rotation_jobs():
    """Resume previously paused rotation jobs."""
    for job_id in _paused_rotation_jobs:
        scheduler.resume_job(job_id)
    logger.info("[SCHEDULER] Resumed %d rotation jobs", len(_paused_rotation_jobs))
    _paused_rotation_jobs.clear()


def init_scheduler(app):
    """
    初始化调度器 — 从数据库加载调度配置，动态注册任务
    """
    global _scheduler_app
    _scheduler_app = app

    app.config['SCHEDULER_API_ENABLED'] = True
    app.config['SCHEDULER_TIMEZONE'] = 'Asia/Shanghai'

    scheduler.init_app(app)

    # 容灾恢复：扫描pending_password
    scan_pending_passwords()

    # 从数据库加载并注册改密调度任务
    apply_schedule_jobs()

    # 绕行检测（每小时）
    scheduler.add_job(
        id='detect_bypass_login',
        func=detect_bypass_login,
        trigger='cron',
        minute=0,
        second=0
    )

    # 资产健康检查（每小时）
    scheduler.add_job(
        id='asset_health_check',
        func=check_assets_connectivity,
        trigger='interval',
        hours=1
    )

    # REMOVED: Progressive re-encrypt job — replaced by synchronous re-encryption in T4
    # scheduler.add_job(
    #     id='progressive_re_encrypt',
    #     func=_progressive_re_encrypt,
    #     trigger='interval',
    #     seconds=30
    # )

    # 审计日志自动锁定（每日凌晨3点，锁定30天前的日志）
    scheduler.add_job(
        id='auto_lock_audit_logs',
        func=auto_lock_old_logs,
        trigger='cron',
        hour=3,
        minute=0
    )

    scheduler.start()

    logger.info("调度器初始化完成")


def shutdown_scheduler(wait=True, timeout=10):
    """Gracefully shutdown the scheduler."""
    if not scheduler.running:
        logger.info("[SCHEDULER] Scheduler not running, skipping shutdown")
        return
    logger.info("[SCHEDULER] Shutting down scheduler...")
    try:
        scheduler.shutdown(wait=False)
        logger.info("[SCHEDULER] Scheduler shutdown complete")
    except Exception as e:
        logger.error("[SCHEDULER] Scheduler shutdown error: %s", e)