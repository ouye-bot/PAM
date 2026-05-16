FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# 安装 SSH + 日志服务 + 必装tzdata（修复时区）
RUN apt-get update && apt-get install -y openssh-server rsyslog tzdata && apt-get clean

# SSH 原有配置（保留）
RUN mkdir -p /var/run/sshd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'SyslogFacility AUTH' >> /etc/ssh/sshd_config
RUN echo 'LogLevel INFO' >> /etc/ssh/sshd_config
RUN echo 'root:123456' | chpasswd

# 日志文件
RUN touch /var/log/auth.log && chmod 666 /var/log/auth.log
RUN echo 'auth.*  /var/log/auth.log' >> /etc/rsyslog.conf

# 修复启动脚本（时区 + 日志 + SSH）
RUN cat > /start.sh <<'EOF'
#!/bin/bash
ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo "Asia/Shanghai" > /etc/timezone
rsyslogd &
sleep 1
/usr/sbin/sshd -D
EOF

RUN chmod +x /start.sh

EXPOSE 22
CMD ["/start.sh"]
