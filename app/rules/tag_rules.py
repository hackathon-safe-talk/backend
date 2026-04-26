"""
Rule-based tagging definitions for automatic threat classification.
These regex patterns are matched against threat fields during ingestion.
"""

URL_RULES: list[tuple[str, str]] = [
    (r"\.apk$", "apk_distribution"),
    (r"\.exe$", "exe_distribution"),
    (r"(login|verify|secure|update|confirm)", "phishing_keywords_in_url"),
    (r"\.(xyz|tk|ml|ga|cf|top|buzz|club|icu|cam)(/|$)", "suspicious_tld"),
    (r"(sqb|bank|click|payme|uzum)", "brand_impersonation"),
    (r"bit\.ly|tinyurl|t\.co|is\.gd|rb\.gy", "url_shortener"),
    (r"t\.me/", "telegram_link"),
]

SENDER_RULES: list[tuple[str, str]] = [
    (r"^\+\d{5,}$", "phone_number_sender"),
    (r"^[A-Za-z]+$", "alphanumeric_sender"),
]

MESSAGE_RULES: list[tuple[str, str]] = [
    (r"(karta|card).*?(bloklandi|blocked)", "card_block_scam"),
    (r"(kod|code|OTP).*?(yuboring|send|kiriting|enter)", "otp_harvesting"),
    (r"(yutuq|prize|bonus|sovg'a|gift)", "prize_scam"),
    (r"(premium|stars).*?(free|tekin|bepul)", "telegram_premium_scam"),
    (r"(bu senmi|is this you|senmisan|rasmga qara)", "curiosity_lure"),
]

FILE_RULES: list[tuple[str, str]] = [
    ("apk", "apk_malware"),
    ("exe", "windows_malware"),
    ("zip", "archive_attachment"),
    ("rar", "archive_attachment"),
]
