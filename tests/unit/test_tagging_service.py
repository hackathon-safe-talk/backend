"""Unit tests for the rule-based auto-tagging service."""

from unittest.mock import MagicMock

from app.services.tagging_service import apply_auto_tags


def _threat(url=None, sender=None, message=None, file_name=None):
    t = MagicMock()
    t.detected_url = url
    t.sender_name = sender
    t.message_truncated = message
    t.detected_file_name = file_name
    return t


class TestUrlRules:
    def test_apk_download(self):
        assert "apk_distribution" in apply_auto_tags(_threat(url="http://evil.com/malware.apk"))

    def test_exe_download(self):
        assert "exe_distribution" in apply_auto_tags(_threat(url="http://evil.com/virus.exe"))

    def test_suspicious_tld_xyz(self):
        assert "suspicious_tld" in apply_auto_tags(_threat(url="http://phish.xyz/page"))

    def test_suspicious_tld_tk(self):
        assert "suspicious_tld" in apply_auto_tags(_threat(url="http://scam.tk/login"))

    def test_brand_impersonation_sqb(self):
        assert "brand_impersonation" in apply_auto_tags(_threat(url="http://sqb-online.com"))

    def test_brand_impersonation_payme(self):
        assert "brand_impersonation" in apply_auto_tags(_threat(url="https://payme-uz.xyz"))

    def test_url_shortener_bitly(self):
        assert "url_shortener" in apply_auto_tags(_threat(url="https://bit.ly/abc123"))

    def test_url_shortener_tinyurl(self):
        assert "url_shortener" in apply_auto_tags(_threat(url="https://tinyurl.com/xyz"))

    def test_telegram_link(self):
        assert "telegram_link" in apply_auto_tags(_threat(url="https://t.me/scamgroup"))

    def test_phishing_keyword_login(self):
        assert "phishing_keywords_in_url" in apply_auto_tags(
            _threat(url="https://secure-login.com/verify")
        )

    def test_phishing_keyword_confirm(self):
        assert "phishing_keywords_in_url" in apply_auto_tags(
            _threat(url="http://bank-confirm.com")
        )


class TestSenderRules:
    def test_phone_number_sender(self):
        assert "phone_number_sender" in apply_auto_tags(_threat(sender="+998901234567"))

    def test_short_phone_number_no_tag(self):
        # +1234 has only 4 digits — below the 5-digit threshold
        assert "phone_number_sender" not in apply_auto_tags(_threat(sender="+1234"))

    def test_alphanumeric_sender(self):
        assert "alphanumeric_sender" in apply_auto_tags(_threat(sender="SafeBank"))

    def test_mixed_sender_no_alphanumeric_tag(self):
        assert "alphanumeric_sender" not in apply_auto_tags(_threat(sender="Bank123"))


class TestMessageRules:
    def test_card_block_scam(self):
        assert "card_block_scam" in apply_auto_tags(
            _threat(message="Sizning kartangiz bloklandi!")
        )

    def test_card_block_english(self):
        assert "card_block_scam" in apply_auto_tags(
            _threat(message="Your card has been blocked")
        )

    def test_otp_harvesting(self):
        assert "otp_harvesting" in apply_auto_tags(
            _threat(message="SMS kodini yuboring")
        )

    def test_prize_scam_yutuq(self):
        assert "prize_scam" in apply_auto_tags(
            _threat(message="Siz yutuq yutdingiz! Bonus olish uchun")
        )

    def test_prize_scam_gift(self):
        assert "prize_scam" in apply_auto_tags(
            _threat(message="Maxsus sovg'a sizni kutmoqda!")
        )

    def test_curiosity_lure(self):
        assert "curiosity_lure" in apply_auto_tags(
            _threat(message="Bu senmi? Rasmga qara")
        )


class TestFileRules:
    def test_apk_file(self):
        assert "apk_malware" in apply_auto_tags(_threat(file_name="installer.apk"))

    def test_exe_file(self):
        assert "windows_malware" in apply_auto_tags(_threat(file_name="setup.exe"))

    def test_zip_file(self):
        assert "archive_attachment" in apply_auto_tags(_threat(file_name="docs.zip"))

    def test_rar_file(self):
        assert "archive_attachment" in apply_auto_tags(_threat(file_name="files.rar"))

    def test_pdf_file_no_tag(self):
        tags = apply_auto_tags(_threat(file_name="report.pdf"))
        assert "apk_malware" not in tags
        assert "windows_malware" not in tags

    def test_file_without_extension(self):
        # Should not raise
        tags = apply_auto_tags(_threat(file_name="somefile"))
        assert isinstance(tags, list)


class TestGeneral:
    def test_clean_threat_has_no_tags(self):
        assert apply_auto_tags(_threat()) == []

    def test_output_is_sorted(self):
        tags = apply_auto_tags(_threat(url="https://bit.ly/x.apk", message="Yutuq sovg'a!"))
        assert tags == sorted(tags)

    def test_no_duplicate_tags(self):
        tags = apply_auto_tags(_threat(url="http://sqb-bank.xyz/login"))
        assert len(tags) == len(set(tags))

    def test_multiple_rule_categories_combine(self):
        # URL tag + file tag
        tags = apply_auto_tags(_threat(url="http://evil.xyz", file_name="drop.apk"))
        assert "suspicious_tld" in tags
        assert "apk_malware" in tags
