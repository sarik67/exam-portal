"""
Database connection with persistent connection pooling.
Replaces per-request connect/disconnect with a pool — handles 1000+ concurrent users.
"""

import pymysql
from pymysql.cursors import DictCursor
from contextlib import contextmanager
from dbutils.pooled_db import PooledDB
import config

# ── Connection pool (created once at app start) ────────────────────────────
# mincached  : connections kept open even when idle
# maxcached  : max idle connections sitting in the pool
# maxconnections : hard cap — raise 503 beyond this instead of hanging
# blocking   : True  → wait for a free connection (safe)
#              False → raise error immediately (fail-fast)
_pool = PooledDB(
    creator=pymysql,
    mincached=5,           # keep 5 connections warm always
    maxcached=20,          # up to 20 idle connections cached
    maxconnections=100,    # total cap (MySQL default is 151)
    blocking=True,         # queue requests instead of erroring
    ping=1,                # ping before handing out a connection
    host=config.DB_CONFIG['host'],
    user=config.DB_CONFIG['user'],
    password=config.DB_CONFIG['password'],
    database=config.DB_CONFIG['database'],
    charset=config.DB_CONFIG['charset'],
    cursorclass=DictCursor,
    autocommit=False,
)


def get_db_connection():
    """Borrow a connection from the pool (thread-safe)."""
    return _pool.connection()


@contextmanager
def get_db():
    """
    Context manager: borrow connection from pool, commit on success,
    rollback on error, and return connection to pool when done.
    """
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()   # returns connection to pool (does NOT close TCP socket)
