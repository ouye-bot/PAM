#!/usr/bin/env python3
"""Database migration script - Add MFA fields"""

import pymysql
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '3306')),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'pam')
}

def migrate_database():
    """Execute database migration"""
    try:
        # Connect to database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()
        
        print("Starting database migration...")
        
        # Check and add totp_secret column
        cursor.execute("SHOW COLUMNS FROM users LIKE 'totp_secret'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(32) NULL")
            print("Added totp_secret column successfully")
        else:
            print("totp_secret column already exists")
        
        # Check and add totp_enabled column
        cursor.execute("SHOW COLUMNS FROM users LIKE 'totp_enabled'")
        if cursor.fetchone() is None:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT FALSE")
            print("Added totp_enabled column successfully")
        else:
            print("totp_enabled column already exists")
        
        # Commit changes
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
