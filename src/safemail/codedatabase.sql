USE python;
GO






CREATE TABLE users (
  id INT IDENTITY(1,1) PRIMARY KEY,
  username NVARCHAR(100) NOT NULL UNIQUE, -- username chosen by user
  email NVARCHAR(255),
  password_hash NVARCHAR(255),-- hashed password (bcrypt recommended)
  created_at DATETIME DEFAULT GETDATE()
);



-- Stores email accounts that will be fetched via IMAP
CREATE TABLE imap_accounts (
  id INT IDENTITY(1,1) PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),       -- owner of this IMAP account (can be NULL if no owner)
  account_email TEXT NOT NULL,                -- e.g. user@gmail.com
  imap_host TEXT NOT NULL,                    -- e.g. imap.gmail.com
  imap_port INTEGER DEFAULT 993,              -- default IMAP port
  use_ssl INTEGER DEFAULT 1,                  -- 1 = SSL, 0 = no SSL
  app_password_encrypted TEXT,                -- store IMAP app password encrypted
  folder_inbox TEXT DEFAULT 'INBOX',          -- which folder to fetch
  last_checked DATETIME                        -- last time emails were fetched
);


CREATE TABLE emails_text (
 id INT IDENTITY(1,1) PRIMARY KEY,
  imap_account_id INTEGER NOT NULL REFERENCES imap_accounts(id) ON DELETE CASCADE,
  uid TEXT,                -- IMAP UID or Message-ID, unique per mailbox
  message_id TEXT,         -- Message-ID header if present
  subject TEXT,
  from_address TEXT,
  to_addresses TEXT,       -- comma-separated or JSON string of recipients
  date_received DATETIME,  -- received date from email headers
  text_body TEXT,          -- cleaned text (plain text or HTML converted to text)
  has_attachments INTEGER DEFAULT 0,   -- 1 ida 3ndo fichier   0 mkch 
  processed INTEGER DEFAULT 0,         -- 0 = not scanned/phished yet, 1 = scanned
  is_quarantined INTEGER DEFAULT 0,    -- quick flag if email was flagged as suspicious
  quarantined_at DATETIME,             -- datetime when it was marked quarantined
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- Stores metadata for email attachments
CREATE TABLE attachments (
  id INT IDENTITY(1,1) PRIMARY KEY,
  email_id INTEGER REFERENCES emails_text(id) ON DELETE CASCADE,
  filename TEXT,              -- file name
  content_type TEXT,          -- mime type (ex: application/pdf, image/png)
  size_bytes INTEGER,         -- file size
  saved_path TEXT,            -- path on disk where file is stored
  sha256 TEXT,                -- SHA256 hash of file (for deduplication & integrity check)
  suspicious INTEGER DEFAULT 0,  -- 1 if file detected as suspicious
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- Stores emails that are flagged as suspicious / dangerous
CREATE TABLE quarantine (
 id INT IDENTITY(1,1) PRIMARY KEY,
  email_id INTEGER NOT NULL REFERENCES emails_text(id) ON DELETE CASCADE,
  reason TEXT,                -- reason for quarantine (suspicious link, attachment, VirusTotal, etc.)
  quarantined_by TEXT,        -- 'system' or username
  quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- timestamp when it was quarantined
  released INTEGER DEFAULT 0, -- 1 if email was later released from quarantine
  released_at DATETIME        -- timestamp when email was released
);
