"""
AutoSecAudit - User Authentication Subsystem
Provides local SQLite user management, salted password hashing via Werkzeug,
registration, authentication, and session helpers.
"""

import os
import sqlite3
import time
import uuid
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from werkzeug.security import generate_password_hash, check_password_hash

import config

logger = logging.getLogger(__name__)

DB_PATH = Path(config.DATA_DIR) / "users.db"


def _get_db() -> sqlite3.Connection:
    """Get SQLite database connection with row factory."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_user_db() -> None:
    """Initialize the users database table and seed default admin if empty."""
    with _get_db() as conn:
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
        conn.commit()

        # Seed demo user if no users exist
        cursor = conn.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()["count"] == 0:
            demo_user_id = str(uuid.uuid4())
            demo_hash = generate_password_hash("AutoSec@2026", method="pbkdf2:sha256")
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
            conn.commit()
            logger.info("Initialized user database and created default admin account (admin / AutoSec@2026)")


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
        with _get_db() as conn:
            conn.execute("""
                INSERT INTO users (id, username, email, password_hash, full_name, role, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, username, email, pw_hash, full_name or username.capitalize(), role, now, now))
            conn.commit()
            
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
        with _get_db() as conn:
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
            conn.commit()

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


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user dictionary by ID (excluding password hash)."""
    if not user_id:
        return None
    try:
        with _get_db() as conn:
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


# Auto-initialize database schema on import
init_user_db()
