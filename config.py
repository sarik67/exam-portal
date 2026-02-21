"""
Configuration for Online Examination Portal
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Secret key — CHANGE THIS to a random 64-char string in production!
# Generate one: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production-2024')

# Database configuration — override via environment variables in production
_DEFAULT_DB_PASSWORD = 'root123'
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST',     'localhost'),
    'user':     os.environ.get('DB_USER',     'root'),
    'password': os.environ.get('DB_PASSWORD', _DEFAULT_DB_PASSWORD),
    'database': os.environ.get('DB_NAME',     'exam_portal'),
    'charset':  'utf8mb4',
    'cursorclass': None,  # overridden to DictCursor in db.py
}

# Upload configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size

# Session configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

# Production server (Waitress) — threads = concurrent request handlers
# 1000 students ÷ ~50ms avg request time = ~50 threads needed comfortably
WAITRESS_THREADS = int(os.environ.get('WAITRESS_THREADS', 64))
WAITRESS_PORT    = int(os.environ.get('PORT', 5000))
