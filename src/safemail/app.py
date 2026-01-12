from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from .attachment_worker import process_pending_attachments
from .attachment_scanner import vt_lookup_hash
import os

# Import your existing phishing functions
from .phishing import teste_email

# Import the DB connection
from .db import get_db_connection

app = FastAPI(title="Email Phishing Detector API")

class EmailRequest(BaseModel):
    email_id: int
    raw_text: str



def analyze_attachments(email_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filename, content_type, size_bytes, verdict, severity, score
        FROM attachments
        WHERE email_id = ?
    """, (email_id,))

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {
            "count": 0,
            "dangerous": False,
            "report": "",
            "reasons": []
        }

    report_lines = []
    reasons = []
    email_is_dangerous = False

    for file in rows:
        filename, ctype, size, verdict, severity, score = file

        line = f"- **{filename}** ({ctype}, {size} bytes) — Verdict: **{verdict}**"

        # Analyse du verdict
        if verdict is None:
            line += " → Unknown"
            reasons.append(f"Attachment '{filename}' has unknown verdict.")
            email_is_dangerous = True

        elif verdict.upper() == "MALICIOUS":
            line += " → ⚠️ Malicious file detected"
            reasons.append(f"Malicious attachment: {filename}")
            email_is_dangerous = True

        elif verdict.upper() == "SUSPICIOUS":
            line += " → Suspicious file"
            reasons.append(f"Suspicious attachment: {filename}")
            email_is_dangerous = True

        elif verdict.upper() == "SAFE":
            line += " → safe"

        report_lines.append(line)

    final_report = "\n".join(report_lines)

    return {
        "count": len(rows),
        "dangerous": email_is_dangerous,
        "report": final_report,
        "reasons": reasons
    }




def classify_email(email_id, raw_text):
    """
    Analyse un email, ses URLs, mots suspects et pièces jointes,
    met à jour la BDD et génère un rapport professionnel.
    """

    # === 1. Analyse de l'email ===
    email_analysis = teste_email(raw_text)
    
    # === 2. Analyse des attachments existants dans la BDD ===
    attach_analysis = analyze_attachments(email_id)

    # === 3. Détermination de la suspicion ===
    is_suspicious = False
    reasons = []

    # 3.1 Attachments dangereux
    if attach_analysis["dangerous"]:
        is_suspicious = True
        reasons.append("Attachment(s) flagged as suspicious or malicious.")

    # 3.2 URLs malveillantes
    malicious_urls = []
    for vt in email_analysis["vt_results"]:
        report = vt["report"]
        if report.get("malicious_count", 0) > 0:
            is_suspicious = True
            malicious_urls.append(vt["url"])
    if malicious_urls:
        reasons.append(f"Malicious URL(s) detected: {', '.join(malicious_urls)}")

    # 3.3 Mots suspects
    if email_analysis["suspicious_words_count"] >= 2:
        is_suspicious = True
        reasons.append(f"Suspicious words detected: {', '.join(email_analysis['suspicious_words_found'])}")

    # 3.4 Trop de liens
    if len(email_analysis["urls"]) > 3:
        is_suspicious = True
        reasons.append("Email contains excessive number of URLs.")

    # === 4. Mise à jour de la BDD ===
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now()
    if is_suspicious:
        # Mettre en quarantaine
        cursor.execute("""
            UPDATE emails_text
            SET processed = 1,
                is_quarantined = 1,
                quarantined_at = ?
            WHERE id = ?
        """, now, email_id)

        cursor.execute("""
            INSERT INTO quarantine(email_id, reason, quarantined_by)
            VALUES (?, ?, 'system')
        """, email_id, "; ".join(reasons))
    else:
        # Pas de quarantaine
        cursor.execute("""
            UPDATE emails_text
            SET processed = 1,
                is_quarantined = 0
            WHERE id = ?
        """, email_id)

    conn.commit()
    conn.close()

    # === 5. Rapport détaillé pour frontend / API ===
    detailed_report = {
        "email_id": email_id,
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "urls": email_analysis["urls"],
        "suspicious_words": email_analysis["suspicious_words_found"],
        "attachments": attach_analysis["report"]
    }

    return detailed_report



@app.post("/analyze_email")
def analyze_email_route(request: EmailRequest):
    try:
        return classify_email(request.email_id, request.raw_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))























# ======================================================================
#                      IMAP ROUTES 
# ======================================================================


@app.get("/imap/fetch_emails")
def fetch_emails_route():
    """bouchra 3amri hna t7abi tzidi route wa7doukhra diri imap/asemroute"""
    pass  


@app.get("/imap/email/{email_id}")
def get_single_email_route(email_id: int):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, uid, has_attachments, attachments_extracted
        FROM emails_text
        WHERE id = ?
    """, (email_id,))

    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Email not found")

    return {
        "email_id": row.id,
        "uid": row.uid,
        "has_attachments": bool(row.has_attachments),
        "attachments_extracted": bool(row.attachments_extracted)
    }


@app.post("/imap/analyze")
def imap_analyze_email(request: EmailRequest):
    """
    Wrapper IMAP : utilise EXACTEMENT la même logique
    que /analyze_email, sans la modifier.
    """
    try:
        return classify_email(request.email_id, request.raw_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# ======================================================================
#                      USERS ROUTES 
# ======================================================================
# Create user, login, list users…

@app.post("/users/create")
def create_user_route():
    """ malek diri part ta3k hna ta3 creer user  mtnsaych ida kyn parametre tzidih"""
    pass  


@app.post("/users/login")
def login_user_route():
    """malek"""
    pass 


@app.get("/users")
def list_users_route():
    """hadi route lkbira ta3 list users ida 9drty zidiha ns79oha bch ntstiw"""
    pass  



# ======================================================================
#              ATTACHMENTS + VIRUSTOTAL 
# ======================================================================
# Detect attachments, save them, scan with virustotal

@app.get("/attachments/{email_id}")
def extract_attachments_route(email_id: int):
    """
    Retourne les attachments analysés pour un email donné
    (lecture DB uniquement, pas de rescan)
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, filename, content_type, size_bytes,
               verdict, severity, score, sha256
        FROM attachments
        WHERE email_id = ?
        ORDER BY scanned_at DESC
    """, (email_id,))
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return {"email_id": email_id, "count": 0, "attachments": []}

    return {
        "email_id": email_id,
        "count": len(rows),
        "attachments": [
            {
                "attachment_id": r.id,
                "filename": r.filename,
                "content_type": r.content_type,
                "size_bytes": int(r.size_bytes),
                "verdict": r.verdict,
                "severity": r.severity,
                "score": int(r.score),
                "sha256": r.sha256,
            }
            for r in rows
        ]
    }




@app.get("/attachments/scan/{attachment_id}")
def scan_attachment_route(attachment_id: int):
    """
    Re-scan VirusTotal pour un attachment précis
    (lookup hash uniquement)
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT sha256
        FROM attachments
        WHERE id = ?
    """, (attachment_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Attachment not found")

    sha256 = row.sha256
    vt_key = os.getenv("VT_API_KEY")

    if not vt_key:
        raise HTTPException(status_code=400, detail="VirusTotal API key not configured")

    vt_result = vt_lookup_hash(sha256, vt_key)

    return {
        "attachment_id": attachment_id,
        "sha256": sha256,
        "virustotal": vt_result
    }

@app.post("/attachments/scan-pending")
def scan_pending_attachments_route():
    """
    Lance le worker qui :
    - extrait les pièces jointes
    - scanne avec ton scanner
    - stocke les résultats en DB
    """
    try:
        vt_key = os.getenv("VT_API_KEY")
        process_pending_attachments(vt_api_key=vt_key or None)
        return {"status": "ok", "message": "Attachments scanned"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
