# attachment_worker.py – version PRO compatible SQL Server + scanner avancé

import os
import hashlib
from typing import List, Dict, Any, Optional, Tuple
import pyodbc
import imaplib
from email import message_from_bytes, policy

from attachment_scanner import scan_single_attachment  # ton super scanner

# ==========================================================
# CONFIG
# ==========================================================

ATTACH_BASE_DIR = "storage/attachments"

SQL_SERVER_CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=python;"
    "Trusted_Connection=yes;"
)

# ==========================================================
# DB UTILITIES
# ==========================================================

def get_db_connection():
    return pyodbc.connect(SQL_SERVER_CONN_STR)


def get_pending_emails() -> List[Any]:
    """
    Récupère les emails qui ont des pièces jointes NON encore extraites.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, imap_account_id, uid
        FROM emails_text
        WHERE has_attachments = 1 AND attachments_extracted = 0
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_imap_account(imap_account_id: int) -> Optional[Any]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT account_email, imap_host, imap_port,
               app_password_encrypted, use_ssl
        FROM imap_accounts
        WHERE id = ?
    """, (imap_account_id,))
    row = cur.fetchone()
    conn.close()
    return row


def mark_email_attachments_extracted(email_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE emails_text
        SET attachments_extracted = 1
        WHERE id = ?
    """, (email_id,))
    conn.commit()
    conn.close()


def insert_attachment_record(
    email_id: int,
    filename: str,
    content_type: str,
    size_bytes: int,
    saved_path: str,
    sha256: str,
    scan_report: Dict[str, Any]
):
    """
    Insère toutes les données du scan dans la table attachments.
    Compatible avec les nouvelles colonnes.
    """
    verdict      = scan_report.get("verdict")
    severity     = scan_report.get("severity")
    score        = scan_report.get("score")
    risk_summary = scan_report.get("risk_summary")
    confidence   = scan_report.get("confidence")

    vt = scan_report.get("virus_total", {}) or {}

    vt_malicious  = vt.get("malicious", 0)
    vt_suspicious = vt.get("suspicious", 0)
    vt_undetected = vt.get("undetected", 0)
    vt_harmless   = vt.get("harmless", 0)

    suspicious_flag = 1 if verdict in ("malicious", "suspicious") else 0

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO attachments (
            email_id, filename, content_type, size_bytes,
            saved_path, sha256, suspicious,
            verdict, severity, score,
            risk_summary, confidence,
            vt_malicious, vt_suspicious, vt_undetected, vt_harmless,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
    """, (
        email_id, filename, content_type, size_bytes,
        saved_path, sha256, suspicious_flag,
        verdict, severity, score,
        risk_summary, confidence,
        vt_malicious, vt_suspicious, vt_undetected, vt_harmless
    ))

    conn.commit()
    conn.close()

# ==========================================================
# FILE HELPERS
# ==========================================================

def decrypt_password(encrypted: str) -> str:
    # A remplacer par ton vrai déchiffrement
    return encrypted


def compute_sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def safe_filename(name: str) -> str:
    return "".join(c for c in (name or "file") if c.isalnum() or c in (" ", ".", "_", "-"))


def save_attachment_to_disk(imap_account_id: int, uid: str, filename: str, payload: bytes):
    sha = compute_sha256(payload)
    safe_name = safe_filename(filename)
    folder = os.path.join(ATTACH_BASE_DIR, str(imap_account_id), str(uid))
    os.makedirs(folder, exist_ok=True)

    path = os.path.join(folder, f"{sha}_{safe_name}")

    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(payload)

    size = os.path.getsize(path)
    return path, size, sha

# ==========================================================
# IMAP HELPERS
# ==========================================================

def connect_imap(host, user, password, port, use_ssl):
    return (imaplib.IMAP4_SSL(host, port) if use_ssl else imaplib.IMAP4(host, port)).login(user, password)


def fetch_email_raw(host, user, password, uid, port, use_ssl):
    if use_ssl:
        M = imaplib.IMAP4_SSL(host, port)
    else:
        M = imaplib.IMAP4(host, port)

    M.login(user, password)
    M.select("INBOX")
    typ, data = M.uid("fetch", uid, "(RFC822)")
    raw = data[0][1] if typ == "OK" else None
    M.logout()
    return raw

# ==========================================================
# ATTACHMENT EXTRACTION
# ==========================================================

def extract_attachments(raw_email: bytes):
    msg = message_from_bytes(raw_email, policy=policy.default)
    results = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True)
            if payload:
                results.append((filename or "unknown", part.get_content_type(), payload))

    return results

# ==========================================================
# MAIN PIPELINE
# ==========================================================

def process_pending_attachments(vt_api_key=None):
    emails = get_pending_emails()
    if not emails:
        print("[INFO] Aucun email à traiter.")
        return

    for e in emails:
        email_id = e.id
        account_id = e.imap_account_id
        uid = str(e.uid)

        print(f"\n[+] Traitement Email {email_id} (UID={uid})")

        acc = get_imap_account(account_id)
        if not acc:
            print("  [-] Compte IMAP introuvable.")
            continue

        raw = fetch_email_raw(
            acc.imap_host,
            acc.account_email,
            decrypt_password(acc.app_password_encrypted),
            uid,
            acc.imap_port,
            bool(acc.use_ssl)
        )

        if not raw:
            print("  [-] Impossible de récupérer le message.")
            continue

        attachments = extract_attachments(raw)

        if not attachments:
            print("  [*] Aucun attachment trouvé.")
            mark_email_attachments_extracted(email_id)
            continue

        for filename, content_type, payload in attachments:
            saved_path, size_bytes, sha256 = save_attachment_to_disk(
                account_id, uid, filename, payload
            )

            att_dict = {
                "filename": filename,
                "content_type": content_type,
                "size": size_bytes,
                "data": payload
            }

            scan_report = scan_single_attachment(att_dict, vt_api_key)
            insert_attachment_record(
                email_id,
                filename,
                content_type,
                size_bytes,
                saved_path,
                sha256,
                scan_report
            )

            print(f"  [+] Scanné : {filename} → {scan_report['verdict']} ({scan_report['score']})")

        mark_email_attachments_extracted(email_id)


if __name__ == "__main__":
    process_pending_attachments(vt_api_key=None)
