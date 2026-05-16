#!/usr/bin/env python3
"""Database migration script - Add sm2_public_key column to users table"""

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

        print("Starting database migration: add sm2_public_key...")

        cursor.execute("SHOW COLUMNS FROM users LIKE 'sm2_public_key'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE users ADD COLUMN sm2_public_key TEXT NULL")
            print("Added sm2_public_key column successfully")
        else:
            print("sm2_public_key column already exists")

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