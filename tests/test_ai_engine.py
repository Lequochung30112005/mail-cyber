# ========================
# tests/test_ai_engine.py
# Unit test cho preprocessing và AI predictor
# ========================

import sys
import os
import pytest
import numpy as np

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ai_engine'))

from ai_engine.preprocessing import clean_text


# ========================
# TEST: PREPROCESSING
# ========================

class TestPreprocessing:

    def test_clean_text_basic(self):
        """Text cơ bản phải trả về chuỗi không rỗng"""
        result = clean_text("Hello world this is a test email")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_clean_text_removes_html(self):
        """Phải xóa HTML tags"""
        result = clean_text("<h1>Hello</h1><p>World</p>")
        assert '<' not in result
        assert '>' not in result

    def test_clean_text_removes_urls(self):
        """Phải xóa hoặc replace URLs"""
        result = clean_text("Visit https://malicious-site.com/click now")
        assert 'https' not in result or 'urltoken' in result

    def test_clean_text_removes_emails(self):
        """Phải xóa địa chỉ email"""
        result = clean_text("Contact us at spam@evil.com for more info")
        assert '@' not in result or 'emailtoken' in result

    def test_clean_text_lowercase(self):
        """Kết quả phải là chữ thường"""
        result = clean_text("URGENT WINNER CLICK HERE NOW")
        assert result == result.lower()

    def test_clean_text_removes_numbers(self):
        """Phải xóa số"""
        result = clean_text("Win 1000000 dollars now")
        assert '1000000' not in result

    def test_clean_text_empty_string(self):
        """String rỗng phải trả về rỗng"""
        assert clean_text("") == ""
        assert clean_text("   ") == ""
        assert clean_text(None) == ""

    def test_clean_text_spam_sample(self):
        """Email spam điển hình phải còn lại các từ khóa sau clean"""
        spam = "URGENT! You have won $1,000,000! Click here to verify your account!"
        result = clean_text(spam)
        # Sau stemming "urgent" → "urgent", "click" → "click"
        assert len(result) > 0

    def test_clean_text_ham_sample(self):
        """Email bình thường phải được làm sạch đúng"""
        ham = "Hi team, please review the attached agenda for tomorrow's meeting."
        result = clean_text(ham)
        assert len(result) > 0

    def test_clean_text_special_characters(self):
        """Phải xóa ký tự đặc biệt"""
        result = clean_text("Hello!!! *** World ### @@@")
        assert '!' not in result
        assert '*' not in result
        assert '#' not in result


# ========================
# TEST: URL FEATURES
# ========================

class TestURLFeatures:

    def setup_method(self):
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
        from backend.core.url_scanner import analyze_url_features, extract_domain
        self.analyze = analyze_url_features
        self.extract_domain = extract_domain

    def test_detect_ip_url(self):
        """Phải phát hiện URL chứa IP"""
        features = self.analyze("http://192.168.1.1/phishing")
        assert features['has_ip'] is True

    def test_detect_shortened_url(self):
        """Phải phát hiện URL rút gọn"""
        features = self.analyze("https://bit.ly/3abc123")
        assert features['is_shortened'] is True

    def test_detect_suspicious_keywords(self):
        """Phải phát hiện từ khóa nguy hiểm trong URL"""
        features = self.analyze("https://login-verify-account.com/reset-password")
        assert features['has_suspicious_keywords'] is True

    def test_safe_url(self):
        """URL bình thường phải có suspicious_score thấp"""
        features = self.analyze("https://www.google.com")
        assert features['suspicious_score'] <= 1

    def test_extract_domain(self):
        """Phải trích xuất đúng domain"""
        assert self.extract_domain("https://www.evil.com/path") == "evil.com"
        assert self.extract_domain("http://subdomain.evil.com") == "subdomain.evil.com"

    def test_http_not_https(self):
        """Phải phát hiện HTTP không bảo mật"""
        features = self.analyze("http://bank-login.com")
        assert features['is_http_not_https'] is True

    def test_very_long_url(self):
        """Phải phát hiện URL quá dài"""
        long_url = "https://evil.com/" + "a" * 200
        features = self.analyze(long_url)
        assert features['is_very_long'] is True


# ========================
# TEST: IMAP FETCHER UTILITIES
# ========================

class TestIMAPUtils:

    def setup_method(self):
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
        from backend.core.imap_fetcher import extract_urls, decode_mime_words
        self.extract_urls = extract_urls
        self.decode_mime_words = decode_mime_words

    def test_extract_urls_basic(self):
        """Phải tìm được URL trong text"""
        text = "Visit https://evil.com and http://spam.org for details"
        urls = self.extract_urls(text)
        assert len(urls) == 2
        assert any("evil.com" in u for u in urls)

    def test_extract_urls_no_duplicates(self):
        """Không được trả về URL trùng"""
        text = "Go to https://evil.com and also https://evil.com again"
        urls = self.extract_urls(text)
        assert len(urls) == 1

    def test_extract_urls_empty(self):
        """Text không có URL phải trả về list rỗng"""
        urls = self.extract_urls("Hello world, no links here.")
        assert urls == []

    def test_decode_mime_words_plain(self):
        """Text thuần túy phải giữ nguyên"""
        result = self.decode_mime_words("Hello World")
        assert result == "Hello World"

    def test_decode_mime_words_empty(self):
        """String rỗng phải trả về rỗng"""
        assert self.decode_mime_words("") == ""
        assert self.decode_mime_words(None) == ""


# ========================
# TEST: OTP SERVICE
# ========================

class TestOTPService:

    def setup_method(self):
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
        from backend.core.otp_service import generate_otp
        self.generate_otp = generate_otp

    def test_otp_is_6_digits(self):
        """OTP phải đúng 6 chữ số"""
        for _ in range(10):
            otp = self.generate_otp()
            assert len(otp) == 6
            assert otp.isdigit()

    def test_otp_in_valid_range(self):
        """OTP phải trong khoảng 100000 - 999999"""
        for _ in range(20):
            otp = int(self.generate_otp())
            assert 100000 <= otp <= 999999

    def test_otp_randomness(self):
        """OTP phải ngẫu nhiên (không bao giờ 10 cái giống nhau)"""
        otps = {self.generate_otp() for _ in range(10)}
        assert len(otps) > 1  # Ít nhất 2 giá trị khác nhau


# ========================
# PYTEST CONFIGURATION
# ========================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])