from apscheduler.schedulers.background import BackgroundScheduler
from safemail.imap_fetcher import fetch_gmail_imap
from safemail.db import get_db_connection

def fetch_all_users_imap():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM imap_accounts")
    accounts = cursor.fetchall()
    conn.close()

    for acc in accounts:
        account_id = acc[0]
        print(f"⏳ Fetching emails for account {account_id}")
        try:
            fetch_gmail_imap(account_id)
        except Exception as e:
            print(f"❌ Error fetching account {account_id}: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_all_users_imap, 'interval', hours=5)
scheduler.start()
