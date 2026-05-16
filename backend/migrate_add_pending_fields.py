#!/usr/bin/env python3
"""Database migration script - Add pending_password and pending_key_version columns"""

import pymysql
from dotenv import load_dotenv
import os

load_dotenv()

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'pam')
}

def migrate_database():
    try:
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        print("Starting database migration: add pending_password and pending_key_version...")

        cursor.execute("SHOW COLUMNS FROM credentials LIKE 'pending_password'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE credentials ADD COLUMN pending_password VARCHAR(255) NULL")
            print("Added pending_password column successfully")
        else:
            print("pending_password column already exists")

        cursor.execute("SHOW COLUMNS FROM credentials LIKE 'pending_key_version'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE credentials ADD COLUMN pending_key_version INT NULL")
            print("Added pending_key_version column successfully")
        else:
            print("pending_key_version column already exists")

        conn.commit()
        print("Database migration completed!")

    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    migrate_database()