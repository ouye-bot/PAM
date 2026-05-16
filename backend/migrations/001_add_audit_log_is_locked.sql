-- Add is_locked column to audit_logs for immutability locking
ALTER TABLE pam_db.audit_logs ADD COLUMN is_locked TINYINT(1) NOT NULL DEFAULT 0;
