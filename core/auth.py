"""
AutoSecAudit - User Authentication Subsystem
Provides local SQLite user management, salted password hashing via Werkzeug,
registration, authentication, and session helpers.
"""

import os
import sys
import sqlite3
import time
import uuid
import logging
import secrets
import contextlib
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from werkzeug.security import generate_password_hash, check_password_hash

import config

logger = logging.getLogger(__name__)

DB_PATH = Path(config.DATA_DIR) / "users.db"


_initialized_dbs = set()


def _ensure_db_initialized() -> None:
    db_key = str(DB_PATH)
    if db_key not in _initialized_dbs:
        _initialized_dbs.add(db_key)
        init_user_db()


def _get_db() -> sqlite3.Connection:
    """Get SQLite database connection with row factory."""
    _ensure_db_initialized()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_user_db() -> None:
    """Initialize the users database table and seed default admin if empty."""
    _initialized_dbs.add(str(DB_PATH))
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(str(DB_PATH))) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    role TEXT DEFAULT 'developer',
                    created_at REAL NOT NULL,
                    last_login REAL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS revoked_sessions (
                    sid TEXT PRIMARY KEY,
                    revoked_at REAL NOT NULL
                )
            """)

            # Seed demo user if no users exist
            cursor = conn.execute("SELECT COUNT(*) as count FROM users")
            if cursor.fetchone()["count"] == 0:
                demo_user_id = str(uuid.uuid4())
                admin_password = os.environ.get("AUTOSEC_ADMIN_PASSWORD")
                if not admin_password:
                    admin_password = secrets.token_urlsafe(16)
                    sys.stderr.write(f"AutoSec default admin password: {admin_password}\n")
                    sys.stderr.flush()

                demo_hash = generate_password_hash(admin_password, method="pbkdf2:sha256")
                conn.execute("""
                    INSERT INTO users (id, username, email, password_hash, full_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    demo_user_id,
                    "admin",
                    "admin@autosec.local",
                    demo_hash,
                    "Security Administrator",
                    "admin",
                    time.time()
                ))
                logger.info("Initialized user database and created default admin account (admin)")


def create_user(username: str, email: str, password: str, full_name: Optional[str] = None, role: str = "developer") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Create a new user account.
    Returns (success: bool, message: str, user_dict: Optional[dict]).
    """
    username = username.strip().lower()
    email = email.strip().lower()
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters long.", None
    if "@" not in email or "." not in email:
        return False, "Please enter a valid email address.", None
    if len(password) < 6:
        return False, "Password must be at least 6 characters long.", None

    user_id = str(uuid.uuid4())
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256")
    now = time.time()

    try:
        with contextlib.closing(_get_db()) as conn:
            with conn:
                conn.execute("""
                    INSERT INTO users (id, username, email, password_hash, full_name, role, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, username, email, pw_hash, full_name or username.capitalize(), role, now, now))
                
                user_data = {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "full_name": full_name or username.capitalize(),
                    "role": role,
                    "created_at": now
                }
                logger.info(f"Successfully registered new user: {username} ({email})")
                return True, "Account created successfully.", user_data
    except sqlite3.IntegrityError as e:
        err_msg = str(e).lower()
        if "username" in err_msg:
            return False, "Username is already taken.", None
        elif "email" in err_msg:
            return False, "Email is already registered.", None
        else:
            return False, "An account with these details already exists.", None
    except Exception as e:
        logger.error(f"Error creating user {username}: {e}")
        return False, f"Registration failed: {str(e)}", None


def verify_user(identifier: str, password: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Verify user credentials by username or email.
    Returns (success: bool, message: str, user_dict: Optional[dict]).
    """
    identifier = identifier.strip().lower()
    if not identifier or not password:
        return False, "Username/Email and password are required.", None

    try:
        with contextlib.closing(_get_db()) as conn:
            with conn:
                cursor = conn.execute("""
                    SELECT * FROM users WHERE username = ? OR email = ?
                """, (identifier, identifier))
                row = cursor.fetchone()

                if not row:
                    return False, "Invalid username or password.", None

                if not check_password_hash(row["password_hash"], password):
                    return False, "Invalid username or password.", None

                # Update last_login
                now = time.time()
                conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, row["id"]))

                user_data = {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "full_name": row["full_name"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "last_login": now
                }
                logger.info(f"User authenticated: {row['username']}")
                return True, "Login successful.", user_data
    except Exception as e:
        logger.error(f"Authentication error for {identifier}: {e}")
        return False, "Authentication service error.", None


# Flask rejects signed session cookies older than 31 days, so a revocation only has to outlive that.
REVOKED_SESSION_RETENTION = 32 * 24 * 3600


def new_session_id() -> str:
    """Random id stored in the session cookie so that a single login can be revoked server-side."""
    return secrets.token_urlsafe(16)


def revoke_session(sid: str, now: Optional[float] = None) -> None:
    """Mark a session id as logged out and drop revocations too old to matter."""
    if not sid:
        return
    now = time.time() if now is None else now
    with contextlib.closing(_get_db()) as conn:
        with conn:
            conn.execute("INSERT OR REPLACE INTO revoked_sessions (sid, revoked_at) VALUES (?, ?)", (sid, now))
            conn.execute("DELETE FROM revoked_sessions WHERE revoked_at < ?",
                         (time.time() - REVOKED_SESSION_RETENTION,))


def is_session_revoked(sid: str) -> bool:
    if not sid:
        return False
    with contextlib.closing(_get_db()) as conn:
        row = conn.execute("SELECT 1 FROM revoked_sessions WHERE sid = ?", (sid,)).fetchone()
    return row is not None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user dictionary by ID (excluding password hash)."""
    if not user_id:
        return None
    try:
        with contextlib.closing(_get_db()) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "full_name": row["full_name"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "last_login": row["last_login"]
                }
            return None
    except Exception as e:
        logger.error(f"Error fetching user by ID {user_id}: {e}")
        return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user dictionary by username (excluding password hash)."""
    if not username:
        return None
    try:
        with contextlib.closing(_get_db()) as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),))
            row = cursor.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "username": row["username"],
                    "email": row["email"],
                    "full_name": row["full_name"],
                    "role": row["role"],
                    "created_at": row["created_at"],
                    "last_login": row["last_login"]
                }
            return None
    except Exception as e:
        logger.error(f"Error fetching user by username {username}: {e}")
        return None


def init_test_session(sess: Any, user_id: str) -> str:
    """Populate a Flask session-like mapping with user_id and a fresh sid."""
    sid = new_session_id()
    sess["user_id"] = user_id
    sess["sid"] = sid
    sess.permanent = True
    return sid


def login_test_client(client: Any, user_id: str) -> str:
    """Shared test helper to establish an authenticated session on a Flask test client."""
    with client.session_transaction() as sess:
        return init_test_session(sess, user_id)

