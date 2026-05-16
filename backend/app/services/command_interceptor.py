"""
Windows PowerShell 高危命令拦截器。

安全边界说明：
- 本模块用于防止误操作和基础攻击
- 不能防御有意的代码混淆（如字符串拼接、Base64编码、反引号混淆）
- 完整的命令审计需结合目标主机Event ID 4104（PowerShell脚本块日志）
- 未来增强方向：受限语言模式（ConstrainedLanguage）+ 4104日志收集
"""

ALIAS_MAP = {
    'ri': 'Remove-Item',
    'rm': 'Remove-Item',
    'del': 'Remove-Item',
    'rd': 'Remove-Item',
    'format': 'Format-Volume',
}

BLOCK_RULES = [
    (r'format\s+[a-zA-Z]:', '磁盘格式化'),
    (r'del\s+/[fFsS].*C:\\\\Windows', '删除系统文件'),
    (r'rd\s+/[sSqQ].*C:\\\\Windows', '删除系统文件'),
    (r'reg\s+delete\s+HKLM', '注册表删除'),
    (r'reg\s+delete\s+HKCU', '注册表删除'),
    (r'Remove-Item\s+-Path\s+C:\\\\Windows', 'PowerShell删除系统'),
    (r'Stop-Computer', '关机'),
    (r'Restart-Computer', '重启'),
    (r'shutdown\s', '关机/重启'),
]

def _normalize_command(cmd: str) -> str:
    normalized = cmd.strip()
    for alias, full_cmd in ALIAS_MAP.items():
        parts = normalized.split()
        if parts and parts[0].lower() == alias:
            parts[0] = full_cmd
            normalized = ' '.join(parts)
            break
    return normalized

def intercept_command(cmd: str) -> tuple:
    """
    拦截高危PowerShell命令。

    安全边界：
    - 基于正则匹配，无法防御Base64编码、字符串拼接、反引号混淆等绕过方式
    - 适用于Web PowerShell终端的命令执行路径，不能替代主机侧安全日志审计
    - 完整的命令审计需结合目标主机的Event ID 4104（PowerShell脚本块日志）

    Args:
        cmd: 用户输入的原始PowerShell命令

    Returns:
        (True, rule_name, None) 表示命令被拦截，rule_name为触发的规则名称
        (False, "", None) 表示命令通过安全检查
    """
    import re
    sub_commands = cmd.split('|')
    for sub_cmd in sub_commands:
        normalized = _normalize_command(sub_cmd.strip())
        for pattern, rule_name in BLOCK_RULES:
            if re.search(pattern, normalized, re.IGNORECASE):
                return (True, rule_name, None)
    return (False, "", None)