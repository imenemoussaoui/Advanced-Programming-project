import imaplib
import email
from email.header import decode_header
from safemail.db import get_db_connection
from datetime import datetime

def fetch_gmail_imap(account_id: int, fetch_limit=5):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT account_email, app_password_encrypted, last_checked
            FROM imap_accounts
            WHERE id = ?
        """, (account_id,))
        acc = cursor.fetchone()

        if not acc:
            print(f"❌ No IMAP account with ID {account_id}")
            return

        email_addr, password, last_checked = acc
        print(f"📧 Connecting to IMAP account {email_addr}...")

        # Connexion IMAP
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_addr, password)
        imap.select("INBOX")

        # Recherche emails
        status, messages = imap.search(None, "ALL")
        if status != "OK":
            print(f"❌ IMAP search failed for {email_addr}")
            return

        ids = messages[0].split()
        if not ids:
            print(f"ℹ️ No emails found in {email_addr}")
            return

        # Limiter aux emails récents
        recent_ids = ids[-fetch_limit:]
        print(f"🔹 Fetching {len(recent_ids)} emails from {email_addr}")

        for uid in recent_ids:
            try:
                status, msg_data = imap.fetch(uid, "(RFC822)")
                if status != "OK":
                    print(f"❌ Failed to fetch email UID {uid.decode()}")
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                subject = decode_mime(msg.get("Subject"))
                from_addr = msg.get("From")
                to_addr = msg.get("To")
                body = get_body(msg)

                cursor.execute("""
                    INSERT INTO emails_text
                    (imap_account_id, uid, subject, from_address, to_addresses, text_body, processed, is_quarantined, date_received)
                    VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
                """, (
                    account_id,
                    uid.decode(),
                    subject,
                    from_addr,
                    to_addr,
                    body,
                    datetime.now()
                ))

            except Exception as e:
                print(f"❌ Error processing email UID {uid.decode()}: {e}")

        # Mettre à jour last_checked
        cursor.execute("""
            UPDATE imap_accounts
            SET last_checked = ?
            WHERE id = ?
        """, (datetime.now(), account_id))

        conn.commit()
        print(f"✅ Finished fetching for {email_addr}")

    except imaplib.IMAP4.error as e:
        print(f"❌ IMAP login/fetch error for {email_addr}: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        conn.close()
        try:
            imap.logout()
        except:
            pass

def decode_mime(s):
    if not s:
        return ""
    parts = decode_header(s)
    text = ""
    for p, enc in parts:
        if isinstance(p, bytes):
            text += p.decode(enc or "utf-8", errors="ignore")
        else:
            text += p
    return text

def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""
