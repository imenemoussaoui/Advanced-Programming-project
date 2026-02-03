import hashlib
from safemail.db import get_db_connection

# --- Step 1: hashing functions ---
def hash_password(password: str) -> str:
    """Convert password into SHA256 hash"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hash_value: str) -> bool:
    """Check password against stored hash"""
    return hash_password(password) == hash_value

# --- Step 2: signup ---
def create_user_db(username, email, password):
    conn = get_db_connection()
    cur = conn.cursor()

    password_hash = password  # ou hash si tu veux

    # INSERT le user et récupérer son ID
    cur.execute("""
        INSERT INTO users (username, email, password_hash)
        OUTPUT INSERTED.id
        VALUES (?, ?, ?)
    """, (username, email, password_hash))

    user_id = cur.fetchone()[0]  # Récupère l'ID généré

    conn.commit()
    conn.close()

    return user_id

       

# --- Step 3: login verification ---
def verify_user_db(username, password):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    return verify_password(password, row[0])  # <-- check against SHA256 hash
