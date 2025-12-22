# users.py
from datetime import datetime, timedelta
from typing import Optional
from users.db import get_conn
from users.security import hash_password, check_password
from users.validator import validate_email, password_strength


# Configuration: lockout thresholds
MAX_FAILED = 5
LOCKOUT_MINUTES = 15

class UserError(Exception):
    pass

def exists_by_username_or_email(username: str, email: str) -> Optional[str]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT username, email FROM users WHERE username=? OR email=?", (username, email))
        row = cur.fetchone()
        return row

def create_user(username: str, email: str, password: str, role: str = "user") -> int:
    # Basic validation
    if len(username) < 3:
        raise UserError("username too short")
    if not validate_email(email):
        raise UserError("invalid email")
    ok, msg = password_strength(password)
    if not ok:
        raise UserError(msg)

    # Check uniqueness
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email))
        if cur.fetchone():
            raise UserError("username or email already in use")

        pwd_hash = hash_password(password)
        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, pwd_hash, role, now, now))
        conn.commit()
        return cur.lastrowid

def _is_locked(row) -> bool:
    # row expected: (id, failed_logins, last_failed_login, is_active, password_hash, username)
    id_, failed_logins, last_failed_str, is_active, *_ = row
    if failed_logins is None:
        return False
    if failed_logins < MAX_FAILED:
        return False
    if not last_failed_str:
        return False
    last_failed = datetime.fromisoformat(last_failed_str)
    if datetime.utcnow() - last_failed < timedelta(minutes=LOCKOUT_MINUTES):
        return True
    return False

def login(email: str, password: str) -> dict:
    """
    Returns a dict with user info on success, raises UserError on failure.
    This function intentionally does not create sessions or tokens (see notes).
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, failed_logins, last_failed_login, is_active, password_hash, username FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            raise UserError("User not found")

        user_id, failed_logins, last_failed_login, is_active, password_hash, username = row

        # check active
        if not is_active:
            raise UserError("Account disabled")

        # lockout check
        if _is_locked((user_id, failed_logins, last_failed_login, is_active)):
            raise UserError(f"Account locked due to multiple failed attempts. Try again later.")

        # verify password
        if check_password(password, password_hash):
            # reset failed logins
            cur.execute("UPDATE users SET failed_logins=0, last_failed_login=NULL WHERE id=?", (user_id,))
            conn.commit()
            return {"id": user_id, "username": username, "email": email}
        else:
            # increment failed logins
            now = datetime.utcnow().isoformat()
            new_failed = (failed_logins or 0) + 1
            cur.execute("UPDATE users SET failed_logins=?, last_failed_login=? WHERE id=?", (new_failed, now, user_id))
            conn.commit()
            raise UserError("Incorrect password")

def get_user(user_id: int) -> Optional[dict]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        if not row:
            return None
        keys = ["id", "username", "email", "role", "is_active", "created_at", "updated_at"]
        return dict(zip(keys, row))

def find_user_by_email(email: str) -> Optional[dict]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, role, is_active, created_at, updated_at FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            return None
        keys = ["id", "username", "email", "role", "is_active", "created_at", "updated_at"]
        return dict(zip(keys, row))

def update_user(user_id: int, username: Optional[str]=None, email: Optional[str]=None, role: Optional[str]=None, is_active: Optional[int]=None):
    if email and not validate_email(email):
        raise UserError("invalid email")
    fields = []
    values = []
    if username:
        if len(username) < 3:
            raise UserError("username too short")
        fields.append("username = ?")
        values.append(username)
    if email:
        fields.append("email = ?")
        values.append(email)
    if role:
        fields.append("role = ?")
        values.append(role)
    if is_active is not None:
        fields.append("is_active = ?")
        values.append(int(is_active))
    if not fields:
        raise UserError("nothing to update")
    fields.append("updated_at = ?")
    values.append(datetime.utcnow().isoformat())
    values.append(user_id)
    query = f"UPDATE users SET {', '.join(fields)} WHERE id=?"
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(query, values)
        conn.commit()
        return cur.rowcount

def update_password(user_id: int, new_password: str):
    ok, msg = password_strength(new_password)
    if not ok:
        raise UserError(msg)
    new_hash = hash_password(new_password)
    now = datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (new_hash, now, user_id))
        conn.commit()
        return cur.rowcount

def disable_user(user_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_active=0, updated_at=? WHERE id=?", (datetime.utcnow().isoformat(), user_id))
        conn.commit()
        return cur.rowcount

def delete_user(user_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        return cur.rowcount
