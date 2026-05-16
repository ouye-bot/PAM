#!/usr/bin/env python3
"""Database migration script - Add Phase 3/4 fields: allowed_roles, previous_passwords"""

import pymysql
from dotenv import load_dotenv
import os

load_dotenv()

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'pam_system')
}

def migrate_database():
    try:
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        print("Starting Phase 3/4 database migration...")

        cursor.execute("SHOW COLUMNS FROM assets LIKE 'allowed_roles'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE assets ADD COLUMN allowed_roles VARCHAR(255) DEFAULT 'admin'")
            cursor.execute("UPDATE assets SET allowed_roles = 'admin' WHERE allowed_roles IS NULL")
            print("Added allowed_roles column to assets table")
        else:
            print("allowed_roles column already exists")

        cursor.execute("SHOW COLUMNS FROM credentials LIKE 'previous_passwords'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE credentials ADD COLUMN previous_passwords TEXT")
            cursor.execute("UPDATE credentials SET previous_passwords = '[]' WHERE previous_passwords IS NULL")
            print("Added previous_passwords column to credentials table")
        else:
            print("previous_passwords column already exists")

        conn.commit()
        cursor.close()
        conn.close()
        print("Migration completed successfully!")
    except Exception as e:
        print(f"Migration failed: {e}")
        raise

if __name__ == '__main__':
    migrate_database()
