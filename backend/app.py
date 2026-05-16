from flask import Flask, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from dotenv import load_dotenv
import os
from datetime import datetime

# 初始化日志框架（必须在其他所有操作之前）
from app.utils.logger import init_logging, get_logger
init_logging()
logger = get_logger('app')

# 加载环境变量
load_dotenv()

# 创建Flask应用
app = Flask(__name__)

# 配置CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 配置数据库连接
db_user = os.getenv('DB_USER', 'root')
db_password = os.getenv('DB_PASSWORD')
if not db_password:
    raise RuntimeError(
        "环境变量 DB_PASSWORD 未配置，系统无法连接数据库。\n"
        "请设置环境变量 DB_PASSWORD 为数据库密码。"
    )
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', '3306')
db_name = os.getenv('DB_NAME', 'pam_system')

app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600
}

# 导入db对象
from app import db

# 初始化数据库
try:
    db.init_app(app)
    # 导入模型，确保它们被注册
    from app.models import Asset, Credential, KeyVersion, RotationTask, SessionRecord, User, BypassExemption
except Exception as e:
    logger.error("数据库连接失败", exc_info=True)
    # 即使数据库连接失败，也继续运行应用

# 注册蓝图
from app.api import asset_bp, rotation_bp, session_bp, proxy_bp, bypass_bp, audit_bp, dashboard_bp, auth_bp, key_bp, compliance_bp
from app.api.system import system_bp
from app.api.users import users_bp, me_bp
app.register_blueprint(asset_bp)
app.register_blueprint(rotation_bp)
app.register_blueprint(session_bp)
app.register_blueprint(proxy_bp)
app.register_blueprint(bypass_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(key_bp)
app.register_blueprint(system_bp)
app.register_blueprint(users_bp)
app.register_blueprint(me_bp)
app.register_blueprint(compliance_bp)

# 初始化SocketIO — 优先使用Redis消息队列，不可用时回退内存模式
import os
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
socketio_kwargs = {'cors_allowed_origins': '*'}

try:
    import redis
    r = redis.Redis.from_url(redis_url, socket_connect_timeout=2)
    r.ping()
    socketio_kwargs['message_queue'] = redis_url
    logger.info("[SOCKETIO] Using Redis message queue: %s", redis_url)
except Exception as e:
    logger.warning("[SOCKETIO] Redis unavailable (%s), falling back to in-memory mode", e)

socketio = SocketIO(app, **socketio_kwargs)

# 将socketio对象赋值给app模块
import importlib
app_module = importlib.import_module('app')
app_module.socketio = socketio

# 导入SSH路由（必须在socketio初始化之后）
from app.routes import ssh
logger.info("SSH WebSocket routes loaded")

# 导入WinRM路由（必须在socketio初始化之后）
from app.routes import winrm
logger.info("WinRM WebSocket routes loaded")

# 根路径路由
@app.route('/', methods=['GET'])
def index():
    return jsonify({"message": "Hello, PAM System!"})

# 健康检查路由
@app.route('/api/health', methods=['GET'])
def health_check():
    checks = {
        'database': 'unknown',
        'master_key': 'unknown',
        'active_work_key': 'unknown',
        'redis': 'unknown',
        'scheduler': 'unknown',
        'recordings_dir': 'unknown',
    }
    overall = 'ok'

    # 数据库检查
    try:
        from app.models import KeyVersion
        KeyVersion.query.first()
        checks['database'] = 'ok'
    except Exception as e:
        logger.warning("[HEALTH] database check failed: %s", e)
        checks['database'] = 'error'
        overall = 'degraded'

    # 主密钥检查
    try:
        from app.services.crypto_service import get_master_key
        mk = get_master_key()
        checks['master_key'] = 'ok' if mk and len(mk) == 32 else 'invalid'
    except Exception as e:
        logger.warning("[HEALTH] master_key check failed: %s", e)
        checks['master_key'] = 'error'
        overall = 'degraded'

    # 活跃工作密钥检查
    try:
        from app.models import KeyVersion
        from app.services.crypto_service import CryptoService
        active_key = KeyVersion.query.filter_by(status='active').first()
        if active_key:
            wk = CryptoService.decrypt_work_key(active_key.encrypted_key)
            checks['active_work_key'] = 'ok' if wk else 'decrypt_failed'
        else:
            checks['active_work_key'] = 'not_found'
    except Exception as e:
        logger.warning("[HEALTH] active_work_key check failed: %s", e)
        checks['active_work_key'] = 'error'
        overall = 'degraded'

    # Redis 检查
    try:
        import redis as redis_lib
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        r = redis_lib.Redis.from_url(redis_url, socket_connect_timeout=2)
        r.ping()
        checks['redis'] = 'ok'
    except Exception as e:
        logger.warning("[HEALTH] redis check failed: %s", e)
        checks['redis'] = 'error'
        if overall == 'ok':
            overall = 'degraded'

    # 调度器状态
    try:
        from app.scheduler import scheduler
        checks['scheduler'] = 'ok' if scheduler.running else 'stopped'
    except Exception as e:
        logger.warning("[HEALTH] scheduler check failed: %s", e)
        checks['scheduler'] = 'error'

    # 录制目录可写性
    try:
        recordings_dir = os.path.join(os.path.dirname(__file__), 'recordings')
        if not os.path.exists(recordings_dir):
            os.makedirs(recordings_dir, exist_ok=True)
        test_file = os.path.join(recordings_dir, '.health_check_tmp')
        with open(test_file, 'w') as f:
            f.write('ok')
        os.remove(test_file)
        checks['recordings_dir'] = 'ok'
    except Exception as e:
        logger.warning("[HEALTH] recordings_dir check failed: %s", e)
        checks['recordings_dir'] = 'error'

    from app import __version__
    return jsonify({
        'status': overall,
        'version': __version__,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'checks': checks
    })

# === 全局异常处理器 ===
from app.utils.exceptions import AppException, AuthException, PermissionException, NotFoundException, ValidationException, RateLimitException


@app.errorhandler(AppException)
def handle_app_exception(e):
    logger.warning("业务异常: %s", e.message)
    return jsonify({"code": e.status_code, "message": e.message}), e.status_code


@app.errorhandler(ValidationException)
def handle_validation_exception(e):
    logger.warning("参数校验失败: %s", e.message)
    body = {"code": 422, "message": e.message}
    if e.errors:
        body["errors"] = e.errors
    return jsonify(body), 422


@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    logger.exception("未捕获的服务器异常")
    return jsonify({"code": 500, "message": "服务器内部错误，请稍后重试"}), 500


# 初始化数据库函数
def init_db():
    if db is not None:
        with app.app_context():
            try:
                db.create_all()
                logger.info("Database tables created successfully")
            except Exception as e:
                logger.error("Error creating database tables", exc_info=True)

if __name__ == '__main__':
    # 初始化数据库
    init_db()

    # 启动时校验主密钥格式（长度、hex格式），校验失败拒绝启动
    logger.info("=== 校验主密钥格式 ===")
    try:
        from app.services.crypto_service import get_master_key
        get_master_key()
        logger.info("主密钥格式校验通过")
    except RuntimeError as e:
        logger.critical("主密钥格式校验失败，系统拒绝启动: %s", e)
        raise SystemExit(1)

    # 初始化绕行豁免缓存
    with app.app_context():
        from app.services.bypass_exemption import init_cache
        init_cache()

    # 重建审计日志哈希链
    with app.app_context():
        from app.models import AuditLog
        from app.services.crypto_service import CryptoService

        locked_count = AuditLog.query.filter_by(is_locked=True).count()
        if locked_count > 0:
            logger.info("=== 哈希链重建跳过: 存在 %d 条已锁定日志，链已永久冻结 ===", locked_count)
        else:
            logger.info("=== 开始重建审计日志哈希链 ===")

            # 获取所有审计日志，按ID顺序排列
            logs = AuditLog.query.order_by(AuditLog.id).all()

            if logs:
                logger.info("发现 %d 条审计日志", len(logs))

                previous_hash = ''
                updated_count = 0

                for log in logs:
                    # 拼接字符串（包含is_deleted字段）
                    is_deleted = 1 if log.is_deleted else 0
                    data_to_hash = f"{log.log_type}|{log.operator}|{log.source_ip}|{log.target_asset}|{log.operation_detail}|{log.result}|{log.timestamp}|{previous_hash}|{is_deleted}"

                    # 计算哈希值
                    calculated_hash = CryptoService.sm3_hash(data_to_hash)

                    # 更新哈希值
                    log.previous_hash = previous_hash
                    log.current_hash = calculated_hash

                    # 更新previous_hash为当前日志的current_hash
                    previous_hash = calculated_hash

                    updated_count += 1
                    logger.debug("已更新日志 ID: %d, 类型: %s", log.id, log.log_type)

                # 保存到数据库
                try:
                    db.session.commit()
                    logger.info("=== 哈希链重建完成 ===")
                    logger.info("成功更新 %d 条审计日志", updated_count)
                    logger.info("审计日志哈希链已修复")
                except Exception as e:
                    db.session.rollback()
                    logger.error("=== 重建失败 ===", exc_info=True)
            else:
                logger.info("没有审计日志需要处理")

    # 初始化调度器
    from app.scheduler import init_scheduler
    init_scheduler(app)

    # 注册优雅关闭钩子
    import atexit
    from app.scheduler import shutdown_scheduler
    atexit.register(shutdown_scheduler, wait=True, timeout=10)
    logger.info("[APP] Registered graceful shutdown hook")

    # 初始化全局速率限制器
    from app.utils.rate_limiter import start_cleanup_thread
    start_cleanup_thread(interval=300)
    from app.utils.rate_limit_middleware import init_rate_limit_middleware
    init_rate_limit_middleware(app)
    logger.info("[APP] Global rate limiter initialized")

    # 启动Token缓存清理线程（每60秒扫描过期Token）
    from app.services.mysql_proxy import start_token_cleanup_thread
    start_token_cleanup_thread(interval=60)

    # 启动MySQL代理服务线程
    import threading
    from app.services.mysql_proxy import start_proxy_server
    proxy_thread = threading.Thread(target=start_proxy_server, kwargs={'flask_app': app}, daemon=True)
    proxy_thread.start()
    logger.info("[APP] MySQL Proxy service started on port 3307")

    # 启动SocketIO服务
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)