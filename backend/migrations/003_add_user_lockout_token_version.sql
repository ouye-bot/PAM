-- P5-B1: 账户锁定字段
ALTER TABLE users ADD COLUMN failed_login_attempts INT DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until DATETIME NULL;
-- P5-B2: JWT Token 版本号
ALTER TABLE users ADD COLUMN token_version INT DEFAULT 0;
