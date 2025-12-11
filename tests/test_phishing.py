
"""INSERT INTO imap_accounts (user_id, account_email, imap_host, imap_port, use_ssl, folder_inbox)
VALUES (
    1, -- correspond à l'id de l'utilisateur créé ci-dessus
    'test_user@example.com',
    'imap.example.com',
    993,
    1,
    'INBOX'
);





DECLARE @EmailId INT;

INSERT INTO emails_text (
    imap_account_id,
    uid,
    message_id,
    subject,
    from_address,
    to_addresses,
    date_received,
    text_body,
    has_attachments,
    processed,
    is_quarantined,
    quarantined_at,
    attachments_extracted
)
VALUES (
    1,
    'UID123456',
    'MSGID987654@example.com',
    '⚠️ Important: Your Microsoft 365 Credentials Require Immediate Verification',
    'security-update@micros0ft-support.com',
    'test_user@example.com',
    GETDATE(),
'Dear User, ...',
    1,
    0,
    0,
    NULL,
    0
);

-- Récupère l'id généré automatiquement
SET @EmailId = SCOPE_IDENTITY();


INSERT INTO attachments (
    email_id,
    filename,
    content_type,
    size_bytes,
    saved_path,
    sha256,
    suspicious,
    verdict,
    severity,
    score,
    risk_summary,
    confidence,
    vt_malicious,
    vt_suspicious,
    vt_undetected,
    vt_harmless,
    scanned_at
)
VALUES (
    @EmailId,
    'invoice.pdf',
    'application/pdf',
    152300,
    'C:\\emails\\attachments\\invoice.pdf',
    'AABBCCDDEEFF11223344556677889900AABBCCDDEEFF11223344556677889900',
    1,
    'MALICIOUS',
    'HIGH',
    92,
    'Detected as phishing lure with embedded malicious URL',
    0.97,
    5,
    2,
    10,
    0,
    GETDATE()
);

GO"""
