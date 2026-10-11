"""
Unit tests for the User Authentication Subsystem (core/auth.py).
"""
import os
import sys
import tempfile
import sqlite3
from pathlib import Path

sys.path.insert(0, ".")

import core.auth as auth


def test_auth_subsystem():
    print("=" * 50)
    print("TESTING: User Authentication Subsystem")
    print("=" * 50)

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_db = Path(tmpdir) / "test_auth_subsystem.db"
        orig_db = auth.DB_PATH
        auth.DB_PATH = temp_db
        try:
            # 1. Test database initialization with custom admin password
            os.environ["AUTOSEC_ADMIN_PASSWORD"] = "TestAdmin@2026"
            auth.init_user_db()
            admin = auth.verify_user("admin", "TestAdmin@2026")
            assert admin[0] is True, "Configured admin account should authenticate"
            assert admin[2]["username"] == "admin"
            print("[PASS] Admin account initialized and verified with AUTOSEC_ADMIN_PASSWORD")

            # 2. Test user registration
            ok, msg, user = auth.create_user("testdev", "dev@example.com", "SecurePass123!", "Test Developer")
            assert ok is True, f"User creation should succeed: {msg}"
            assert user["username"] == "testdev"
            assert user["email"] == "dev@example.com"
            print("[PASS] User registration succeeded with sanitized credentials")

            # 3. Test duplicate registration prevention
            ok_dup, msg_dup, _ = auth.create_user("testdev", "other@example.com", "Password123")
            assert ok_dup is False, "Duplicate username should be rejected"
            assert "taken" in msg_dup.lower()
            print("[PASS] Duplicate username correctly rejected")

            ok_dup_email, msg_dup_email, _ = auth.create_user("anotherdev", "dev@example.com", "Password123")
            assert ok_dup_email is False, "Duplicate email should be rejected"
            assert "registered" in msg_dup_email.lower()
            print("[PASS] Duplicate email correctly rejected")

            # 4. Test validation constraints
            ok_short, msg_short, _ = auth.create_user("ab", "valid@email.com", "Password123")
            assert ok_short is False, "Short username should be rejected"
            
            ok_bad_email, msg_bad_email, _ = auth.create_user("validuser", "notanemail", "Password123")
            assert ok_bad_email is False, "Invalid email should be rejected"

            ok_short_pw, msg_short_pw, _ = auth.create_user("validuser2", "valid2@email.com", "123")
            assert ok_short_pw is False, "Short password should be rejected"
            print("[PASS] Validation constraints enforced (length, email format, password strength)")

            # 5. Test authentication via username and email
            auth_user, _, user_data = auth.verify_user("testdev", "SecurePass123!")
            assert auth_user is True, "Should authenticate via username"
            assert user_data["username"] == "testdev"

            auth_email, _, user_data_email = auth.verify_user("dev@example.com", "SecurePass123!")
            assert auth_email is True, "Should authenticate via email"
            assert user_data_email["username"] == "testdev"

            auth_bad_pw, msg_bad_pw, _ = auth.verify_user("testdev", "WrongPassword")
            assert auth_bad_pw is False, "Invalid password should fail"
            print("[PASS] Authentication verified for username, email, and rejected for bad credentials")

            # 6. Test fetch by ID
            fetched = auth.get_user_by_id(user["id"])
            assert fetched is not None
            assert fetched["username"] == "testdev"
            assert "password_hash" not in fetched, "Password hash must not be exposed"
            print("[PASS] User retrieval by ID verified with safe projection")
        finally:
            auth.DB_PATH = orig_db
            os.environ.pop("AUTOSEC_ADMIN_PASSWORD", None)

    print("=" * 50)
    print("ALL AUTH TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    test_auth_subsystem()
