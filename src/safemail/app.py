
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from datetime import datetime

from safemail.db import get_db_connection
from safemail.users import create_user_db, verify_user_db,verify_password
from safemail.imap_fetcher import fetch_gmail_imap
from safemail.phishing import teste_email

from fastapi.staticfiles import StaticFiles

from fastapi.responses import FileResponse

from pydantic import BaseModel




app = FastAPI(title="Email Phishing Detector API")

import safemail.scheduler
app.mount("/static", StaticFiles(directory="safemail/static"), name="static")





class EmailRequest(BaseModel):
    email_id: int
    raw_text: str



class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str




class AddImapAccount(BaseModel):
    user_id: int
    gmail: str
    app_password: str

@app.post("/imap/add")
def add_imap_account(account: AddImapAccount):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vérifier si user existe
    cursor.execute("SELECT id FROM users WHERE id = ?", (account.user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Ajouter IMAP account lié au user
    cursor.execute("""
        INSERT INTO imap_accounts (user_id, account_email, app_password_encrypted)
        VALUES (?,?,?)
    """, (account.user_id, account.gmail, account.app_password))
    
    conn.commit()
    conn.close()
    
    return {"status": "IMAP account added"}

@app.get("/")
def home():
    return FileResponse("safemail/static/login.html")


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

        elif verdict.upper() == "CLEAN":
            line += " → Clean"

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




@app.post("/imap/fetch/{account_id}")
def route_fetch(account_id:int):

    fetch_gmail_imap(account_id)

    # scan attachments
    #process_pending_attachments()

    return {"status":"fetched"}



# ======================================================================
#                      USERS ROUTES 
# ======================================================================



# -------- SIGNUP --------
@app.post("/users/create")
def route_create_user(data: UserCreate):
    """
    Crée un user + son compte IMAP directement.
    data: username, email, password
    """
    try:
        # 1️ Créer le user (mot de passe hashé)
        user_id = create_user_db(data.username, data.email, data.password)

        # 2️ Créer le compte IMAP lié à ce user
        # le mot de passe IMAP = mot de passe fourni (non hashé)
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO imap_accounts (user_id, account_email, app_password_encrypted)
            VALUES (?, ?, ?)
        """, (user_id, data.email, data.password))  # mot de passe IMAP lisible
        conn.commit()
        conn.close()

        # 3️ Retour
        return {"status": "created", "user_id": user_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))













# -------- LOGIN --------
@app.post("/users/login")
def route_login(data: UserLogin):
    conn = get_db_connection()
    cur = conn.cursor()

    # Récupère hash du user
    cur.execute("SELECT id, password_hash FROM users WHERE username=?", (data.username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id, password_hash = row

    # Vérification mot de passe hashé
    if not verify_password(data.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "status": "ok",
        "user_id": user_id,
        "username": data.username
    }



# ======================================================================
#              ATTACHMENTS + VIRUSTOTAL 
# ======================================================================
# Detect attachments, save them, scan with virustotal

@app.get("/attachments/{email_id}")
def extract_attachments_route(email_id: int):
    """ hna tkhrji les attachments w t7afdhom f disk wla kima drty"""
    pass  


@app.get("/attachments/scan/{attachment_id}")
def scan_attachment_route(attachment_id: int):
    """hna testi bvirustotal"""
    pass  





#ROUTE — get mailbox
@app.get("/emails/user/{user_id}")
def list_emails(user_id: int):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT e.id,
               e.subject,
               e.from_address,
               e.to_addresses,
               e.text_body,
               e.is_quarantined,
               e.processed
        FROM emails_text e
        JOIN imap_accounts a ON e.imap_account_id = a.id
        WHERE a.user_id = ?
        ORDER BY e.id DESC
    """, (user_id,))

    rows = cur.fetchall()
    conn.close()

    emails = []

    for r in rows:
        emails.append({
            "id": r[0],
            "subject": r[1],
            "from_address": r[2],
            "to_addresses": r[3],
            "text_body": r[4],
            "is_quarantined": bool(r[5]),
            "processed": bool(r[6])
        })

    return emails















@app.get("/emails/detail/{email_id}")
def email_detail(email_id: int):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT subject, from_address, to_addresses,
               text_body, processed, is_quarantined, date_received
        FROM emails_text
        WHERE id = ?
    """, (email_id,))

    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Email not found")

    subject, from_address, to_addresses, text_body, processed, is_quarantined, date_received = row

    # ⚠️ classification seulement si déjà traité
    if processed:
        try:
            report = classify_email(email_id, text_body)
        except Exception as e:
            report = {
                "is_suspicious": False,
                "reasons": [f"classifier error: {e}"],
                "attachments": ""
            }
    else:
        report = {
            "is_suspicious": False,
            "reasons": [],
            "attachments": ""
        }

    return {
        "id": email_id,
        "subject": subject,
        "from_address": from_address,
        "to_addresses": to_addresses,
        "text_body": text_body,
        "date_received": date_received,
        "is_suspicious": report["is_suspicious"],
        "reasons": report["reasons"],
        "attachments": report.get("attachments", ""),
        "is_quarantined": bool(is_quarantined)
    }



@app.get("/emails/user/{user_id}")
def get_user_emails(user_id: int):

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, subject, from_address, to_addresses,
               text_body, is_quarantined, processed
        FROM emails_text
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))

    rows = cur.fetchall()
    conn.close()

    emails = []

    for r in rows:
        emails.append({
            "id": r[0],
            "subject": r[1],
            "from_address": r[2],
            "to_addresses": r[3],
            "text_body": r[4],
            "is_quarantined": bool(r[5]),
            "processed": bool(r[6])
        })

    return emails




@app.get("/imap/accounts/{user_id}")
def get_imap_accounts(user_id:int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, account_email FROM imap_accounts WHERE user_id=?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [{"id":r[0], "email": r[1]} for r in rows]








@app.get("/emails/quarantine/{user_id}")
def list_quarantine_emails(user_id:int):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT e.id, e.subject, e.from_address
        FROM emails_text e
        JOIN imap_accounts a
        ON e.imap_account_id=a.id
        WHERE a.user_id=? AND e.is_quarantined=1
    """,(user_id,))

    rows = cur.fetchall()
    conn.close()

    return [{"id": r[0], "subject": r[1], "from_address": r[2]} for r in rows]
