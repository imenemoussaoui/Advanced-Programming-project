# attachment_worker.py
# VERSION FINALE – Scan des fichiers existants depuis la BD + disque

import os
import hashlib
from typing import Any, Dict, Optional
import pyodbc

from attachment_scanner import scan_single_attachment

# ==========================================================
# CONFIG
# ==========================================================

SQL_SERVER_CONN_STR = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=localhost;"
    "DATABASE=python;"
    "Trusted_Connection=yes;"
)

# ==========================================================
# DB
# ==========================================================

def get_db_connection():
    return pyodbc.connect(SQL_SERVER_CONN_STR)


def get_pending_attachments():
    """
    Récupère les fichiers non encore scannés
    (file_path existe déjà sur disque)
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email_id, filename, content_type, size_bytes, saved_path
        FROM attachments
        WHERE verdict IS NULL
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def update_attachment_scan(
    attachment_id: int,
    scan_report: Dict[str, Any]
):
    verdict      = scan_report.get("verdict")
    severity     = scan_report.get("severity")
    score        = scan_report.get("score")
    risk_summary = scan_report.get("risk_summary")
    confidence   = scan_report.get("confidence")

    vt = scan_report.get("virus_total") or {}
    vt_malicious  = vt.get("malicious", 0)
    vt_suspicious = vt.get("suspicious", 0)
    vt_undetected = vt.get("undetected", 0)
    vt_harmless   = vt.get("harmless", 0)

    suspicious_flag = 1 if verdict in ("malicious", "suspicious") else 0

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE attachments
        SET verdict = ?,
            severity = ?,
            score = ?,
            risk_summary = ?,
            confidence = ?,
            suspicious = ?,
            vt_malicious = ?,
            vt_suspicious = ?,
            vt_undetected = ?,
            vt_harmless = ?,
            scanned_at = GETDATE()
        WHERE id = ?
    """, (
        verdict,
        severity,
        score,
        risk_summary,
        confidence,
        suspicious_flag,
        vt_malicious,
        vt_suspicious,
        vt_undetected,
        vt_harmless,
        attachment_id
    ))
    conn.commit()
    conn.close()

# ==========================================================
# MAIN WORKER
# ==========================================================

def process_pending_attachments(vt_api_key: Optional[str] = None):
    rows = get_pending_attachments()

    if not rows:
        print("[INFO] Aucun fichier à scanner.")
        return

    print(f"[INFO] {len(rows)} fichier(s) à analyser.")

    for r in rows:
        attachment_id = r.id
        email_id = r.email_id
        filename = r.filename
        content_type = r.content_type or "application/octet-stream"
        size_bytes = r.size_bytes
        file_path = r.saved_path

        print(f"\n[+] Scan fichier ID={attachment_id} ({filename})")

        if not file_path or not os.path.exists(file_path):
            print(f"  [-] Fichier introuvable: {file_path}")
            continue

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            att_dict = {
                "filename": filename,
                "content_type": content_type,
                "size": size_bytes or len(data),
                "data": data
            }

            scan_report = scan_single_attachment(att_dict, vt_api_key)

            update_attachment_scan(attachment_id, scan_report)

            print(f"  [+] Verdict: {scan_report['verdict']} | Score: {scan_report['score']}")

        except Exception as e:
            print(f"  [ERROR] Attachment {attachment_id}: {e}")


# ==========================================================
# ENTRYPOINT
# ==========================================================

if __name__ == "__main__":
    process_pending_attachments(vt_api_key=None)