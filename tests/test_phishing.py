

from src.safemail.phishing import (
    find_url_from_text,
    convertir_str,
    separer_headers_body,
    decode_by_header,
    try_decode_probable_base64,
    eliminé_lower_space,
    decodé_eliminé_normalizé,
    is_html,
    detect_suspicious_words
)


long_email = (
    "From: security-update@amazon-support.com\r\n"
    "To: user@example.com\r\n"
    "Subject: URGENT! Your Amazon account has been suspended\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    # Encoded HTML body
    "PGh0bWw+PGJvZHk+CiAgPGgxPlNlY3VyaXR5IEFsZXJ0PC9oMT4KICA8cD5EZWFyIGN1c3RvbWVyLA0K"
    "WW91ciBBbWF6b24gYWNjb3VudCBoYXMgYmVlbiA8c3Ryb25nPnN1c3BlbmRlZDwvc3Ryb25nPiBkdWUg"
    "dW51c3VhbCBhY3Rpdml0eS4gUGxlYXNlIGNvbmZpcm0geW91ciBwYXNzd29yZC48L3A+CiAgPHA+VG8g"
    "dmVyaWZ5IHlvdXIgYWNjb3VudCwgY2xpY2sgdGhlIGJ1dHRvbiBiZWxvdy48L3A+CiAgPGEgaHJlZj0i"
    "aHR0cHM6Ly8xMjMuNDUuNjcuODkvbG9naW4iPkNvbmZpcm0gQWNjb3VudDwvYT4KICA8cD5JZiB5b3Ug"
    "ZG8gbm90IGNvbmZpcm0geW91ciBhY2NvdW50IHdpdGhpbiAyNCBob3VycywgeW91ciBhY2NvdW50IHdp"
    "bGwgYmUgPGI+bG9ja2VkPC9iPi48L3A+CiAgPHA+QmVzdCByZWdhcmRzLDwv cD4KICA8cD5BbWF6b24g"
    "U2VjdXJpdHkgVGVhbTwvcD4KPC9ib2R5PjwvaHRtbD4="
)

# ----------------------------------------------------------------------
# TEST 1: convertir_str
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 1: convertir_str()")
print("==============================")
print(convertir_str(long_email.encode('utf-8')))
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 2: separer_headers_body
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 2: separer_headers_body()")
print("==============================")
headers, body = separer_headers_body(long_email)
print("Headers:\n", headers)
print("\nBody (encoded):\n", body[:200], "...")  # print only part
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 3: decode_by_header
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 3: decode_by_header()")
print("==============================")
decoded_body = decode_by_header(headers, body)
print("Decoded body (first 200 chars):\n", decoded_body[:200], "...")
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 4: try_decode_probable_base64
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 4: try_decode_probable_base64()")
print("==============================")
maybe_decoded = try_decode_probable_base64(body)
print("Result (first 200 chars):\n", maybe_decoded[:200], "...")
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 5: eliminé_lower_space
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 5: eliminé_lower_space()")
print("==============================")
clean_text, clean_lower = eliminé_lower_space(decoded_body)
print("Clean text (first 200 chars):\n", clean_text[:200], "...")
print("Lowercase (first 200 chars):\n", clean_lower[:200], "...")
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 6: decodé_eliminé_normalizé
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 6: decodé_eliminé_normalizé()")
print("==============================")
res = decodé_eliminé_normalizé(long_email)
print("Headers:\n", res["headers_raw"])
print("\nDecoded body (first 200 chars):\n", res["body_decoded"][:200], "...")
print("\nClean:\n", res["clean_text"][:200], "...")
print("\nLower:\n", res["lower_text"][:200], "...")
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 7: is_html
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 7: is_html()")
print("==============================")
print("Is HTML? ->", is_html(decoded_body))
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 8: find_url_from_text
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 8: find_url_from_text()")
print("==============================")
urls = find_url_from_text(decoded_body)
print("URLs found:")
for u in urls:
    print(" •", u)
print("---------------------------------------")


# ----------------------------------------------------------------------
# TEST 9: detect_suspicious_words
# ----------------------------------------------------------------------
print("\n==============================")
print("TEST 9: detect_suspicious_words()")
print("==============================")
count, words = detect_suspicious_words(decoded_body.lower())
print("Count:", count)
print("Words found:", words)
print("---------------------------------------")

print("\n======== ALL TESTS COMPLETED ========")
