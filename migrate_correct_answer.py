"""
Add correct_answer column and short_answer question type.
Run this for existing databases.
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
        cur.execute("ALTER TABLE questions ADD COLUMN correct_answer VARCHAR(500) DEFAULT NULL")
        print("Added correct_answer column to questions")
    except pymysql.err.OperationalError as e:
        if "Duplicate column" in str(e):
            print("correct_answer column already exists")
        else:
            raise
    try:
        cur.execute("ALTER TABLE questions MODIFY COLUMN question_type ENUM('mcq', 'paragraph', 'image', 'short_answer') NOT NULL")
        print("Added short_answer to question_type enum")
    except pymysql.err.OperationalError as e:
        print(f"Note: {e}")
    conn.commit()
conn.close()
print("Migration complete.")
