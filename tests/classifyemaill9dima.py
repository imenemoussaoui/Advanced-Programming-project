from datetime import datetime


def classify_email(email_id, raw_text):
    # Step 1: Analyze email
    
    
    
    
    
    
    analysis = 0

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
    conn =0 #get_db_connection()
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

