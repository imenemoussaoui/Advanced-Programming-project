from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime

# Import your existing phishing functions
from .phishing import teste_email

# Import the DB connection
from .db import get_db_connection

app = FastAPI(title="Email Phishing Detector API")

class EmailRequest(BaseModel):
    email_id: int
    raw_text: str

def classify_email(email_id, raw_text):
    # Step 1: Analyze email
    analysis = teste_email(raw_text)

    # Step 2: Determine if suspicious
    is_suspicious = False
    reason = ""

    for vt in analysis["vt_results"]:
        report = vt["report"]
        if report.get("malicious_count", 0) > 0:
            is_suspicious = True
            reason += f"Malicious URL detected: {vt['url']}. "

    if analysis["suspicious_words_count"] >= 2:
        is_suspicious = True
        reason += f"Suspicious words found: {', '.join(analysis['suspicious_words_found'])}. "

    if len(analysis["urls"]) > 3:
        is_suspicious = True
        reason += "Too many URLs in email. "

    # Step 3: Update database
    conn = get_db_connection()
    cursor = conn.cursor()

    if is_suspicious:
        cursor.execute("""
            UPDATE emails_text
            SET processed = 1,
                is_quarantined = 1,
                quarantined_at = ?
            WHERE id = ?
        """, datetime.now(), email_id)

        cursor.execute("""
            INSERT INTO quarantine(email_id, reason, quarantined_by)
            VALUES (?, ?, 'system')
        """, email_id, reason)

    else:
        cursor.execute("""
            UPDATE emails_text
            SET processed = 1,
                is_quarantined = 0
            WHERE id = ?
        """, email_id)

    conn.commit()
    conn.close()

    return {
        "email_id": email_id,
        "is_suspicious": is_suspicious,
        "reason": reason,
        "analysis": analysis
    }


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
    """bouchra hadi part email"""
    pass  



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
    """ hna tkhrji les attachments w t7afdhom f disk wla kima drty"""
    pass  


@app.get("/attachments/scan/{attachment_id}")
def scan_attachment_route(attachment_id: int):
    """hna testi bvirustotal"""
    pass  