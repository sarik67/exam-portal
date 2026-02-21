"""
Script to create default admin user.
Run this after creating the database to add the initial admin.
Default: username=admin, password=admin123
"""

import bcrypt
from database.db import get_db

def setup_admin():
    """Create default admin user with hashed password."""
    password = b'admin123'
    password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    
    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO admins (username, password_hash) VALUES (%s, %s) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)",
                    ('admin', password_hash)
                )
                print("Admin user created/updated successfully!")
                print("Username: admin")
                print("Password: admin123")
                print("Please change the password after first login in production.")
            except Exception as e:
                print(f"Error: {e}")

if __name__ == '__main__':
    setup_admin()
