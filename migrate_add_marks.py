"""
Add marks column to questions table and total_marks to results.
Run this if you have an existing database.
"""

import pymysql
import config

conn = pymysql.connect(
    host=config.DB_CONFIG['host'],
    user=config.DB_CONFIG['user'],
    password=config.DB_CONFIG['password'],
    database=config.DB_CONFIG['database'],
    charset='utf8mb4'
)

with conn.cursor() as cur:
    try:
        cur.execute("ALTER TABLE questions ADD COLUMN marks INT DEFAULT 1")
        print("Added marks column to questions table")
    except pymysql.err.OperationalError as e:
        if "Duplicate column" in str(e):
            print("marks column already exists")
        else:
            raise
    try:
        cur.execute("ALTER TABLE results ADD COLUMN total_marks DECIMAL(10,2) DEFAULT 0")
        print("Added total_marks column to results table")
    except pymysql.err.OperationalError as e:
        if "Duplicate column" in str(e):
            print("total_marks column already exists")
        else:
            raise
    conn.commit()
conn.close()
print("Migration complete.")
