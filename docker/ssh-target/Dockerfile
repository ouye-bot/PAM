FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 安装 SSH + 日志服务 + 【修复：必装tzdata，解决Ubuntu时区失效核心问题】
RUN apt-get update && apt-get install -y openssh-server rsyslog tzdata && apt-get clean

# SSH 原有配置（完全保留）
RUN mkdir -p /var/run/sshd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'SyslogFacility AUTH' >> /etc/ssh/sshd_config
RUN echo 'LogLevel INFO' >> /etc/ssh/sshd_config
RUN echo 'root:123456' | chpasswd

# 创建日志文件（完全保留）
RUN touch /var/log/auth.log && chmod 666 /var/log/auth.log

# 配置 rsyslog（完全保留）
RUN echo 'auth.*  /var/log/auth.log' >> /etc/rsyslog.conf

# 【修复：重写启动脚本，解决rsyslog假死、时区永久生效】
RUN cat > /start.sh <<'EOF'
#!/bin/bash
# 1. 强制固化北京时间（配合tzdata，永久生效）
ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo "Asia/Shanghai" > /etc/timezone

# 2. 标准方式启动rsyslog（企业级稳定，不后台退出）
rsyslogd -n &
sleep 1

# 3. 启动SSH服务（前台运行，保持容器存活）
/usr/sbin/sshd -D
EOF

RUN chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
