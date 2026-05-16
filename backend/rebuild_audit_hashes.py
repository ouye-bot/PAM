#!/usr/bin/env python3
"""
重新计算审计日志的哈希链
"""

from app import db
from app.models import AuditLog
from app.services.crypto_service import CryptoService


def rebuild_audit_log_hashes():
    """
    重新计算所有审计日志的哈希链
    """
    print("=== 开始重建审计日志哈希链 ===")
    
    # 获取所有审计日志，按ID顺序排列
    logs = AuditLog.query.order_by(AuditLog.id).all()
    
    if not logs:
        print("没有审计日志需要处理")
        return
    
    print(f"发现 {len(logs)} 条审计日志")
    
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
        print(f"已更新日志 ID: {log.id}, 类型: {log.log_type}")
    
    # 保存到数据库
    try:
        db.session.commit()
        print(f"\n=== 哈希链重建完成 ===")
        print(f"成功更新 {updated_count} 条审计日志")
        print("审计日志哈希链已修复")
    except Exception as e:
        db.session.rollback()
        print(f"\n=== 重建失败 ===")
        print(f"错误: {e}")


if __name__ == "__main__":
    rebuild_audit_log_hashes()
