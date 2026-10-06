# ========================
# tests/test_api.py
# Integration test cho FastAPI endpoints
# Dùng TestClient để test không cần server thật
# ========================

import sys
import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))


# Mock database để test không cần MySQL thật
@pytest.fixture(scope="module")
def client():
    """Tạo test client với DB in-memory (SQLite)"""
    import os
    os.environ['DB_HOST']     = 'localhost'
    os.environ['DB_NAME']     = ':memory:'
    os.environ['SECRET_KEY']  = 'test_secret_key_for_testing_only'
    os.environ['MAIL_USERNAME'] = 'test@test.com'
    os.environ['MAIL_PASSWORD'] = 'test'

    # Dùng SQLite để test
    with patch('backend.database.models.DATABASE_URL',
               'sqlite:///./test_cybermail.db'):
        from backend.main import app
        from backend.database.models import create_tables
        create_tables()
        with TestClient(app) as c:
            yield c

    # Cleanup
    if os.path.exists('test_cybermail.db'):
        os.remove('test_cybermail.db')


# ========================
# TEST: HEALTH CHECK
# ========================

class TestHealth:

    def test_root_endpoint(self, client):
        """/ phải trả về 200 và thông tin service"""
        res = client.get("/")
        assert res.status_code == 200
        data = res.json()
        assert data["service"] == "CyberMail Shield API"
        assert data["status"] == "running"

    def test_health_endpoint(self, client):
        """/health phải trả về healthy"""
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"

    def test_docs_available(self, client):
        """/docs phải accessible"""
        res = client.get("/docs")
        assert res.status_code == 200


# ========================
# TEST: AUTHENTICATION
# ========================

class TestAuth:

    def test_register_success(self, client):
        """Đăng ký tài khoản mới phải thành công"""
        res = client.post("/auth/register", json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "Test@123",
            "role": "admin"
        })
        assert res.status_code == 200
        assert "user_id" in res.json()

    def test_register_duplicate_username(self, client):
        """Đăng ký username trùng phải báo lỗi 400"""
        # Đăng ký lần 2 với cùng username
        res = client.post("/auth/register", json={
            "username": "testuser",
            "email": "other@example.com",
            "password": "Test@123"
        })
        assert res.status_code == 400

    def test_login_wrong_password(self, client):
        """Mật khẩu sai phải trả về 401"""
        res = client.post("/auth/login", json={
            "username": "testuser",
            "password": "WrongPassword"
        })
        assert res.status_code == 401

    def test_login_nonexistent_user(self, client):
        """User không tồn tại phải trả về 401"""
        res = client.post("/auth/login", json={
            "username": "ghost_user",
            "password": "anything"
        })
        assert res.status_code == 401

    def test_protected_endpoint_without_token(self, client):
        """Endpoint bảo vệ không có token phải trả về 401"""
        res = client.get("/auth/me")
        assert res.status_code == 401

    def test_protected_endpoint_invalid_token(self, client):
        """Token giả phải bị từ chối"""
        res = client.get("/auth/me",
                         headers={"Authorization": "Bearer fake.token.here"})
        assert res.status_code == 401

    def test_otp_wrong_code(self, client):
        """OTP sai phải trả về 401"""
        res = client.post("/auth/verify-otp", json={
            "email": "test@example.com",
            "otp_code": "000000"
        })
        assert res.status_code == 401


# ========================
# TEST: EMAIL ANALYSIS (với mock AI)
# ========================

class TestEmailAnalysis:

    @pytest.fixture
    def auth_headers(self, client):
        """Helper: Lấy JWT token để test các endpoint cần auth"""
        # Mock OTP flow bằng cách patch verify_otp
        with patch('backend.app.routes.auth.verify_otp', return_value=True):
            # Tạo token trực tiếp
            from backend.app.routes.auth import create_access_token
            from backend.database.models import SessionLocal, User
            from backend.app.routes.auth import hash_password

            db = SessionLocal()
            user = db.query(User).filter(User.username == "testuser").first()
            if user:
                token = create_access_token({"sub": user.id, "role": "admin"})
                db.close()
                return {"Authorization": f"Bearer {token}"}
            db.close()
        return {}

    def test_analyze_text_spam(self, client, auth_headers):
        """Email spam điển hình phải được phát hiện"""
        if not auth_headers:
            pytest.skip("Không có auth token")

        with patch('backend.app.routes.emails.get_predictor_instance') as mock_pred:
            mock_pred.return_value.predict.return_value = {
                'spam_score': 0.92,
                'spam_percent': 92.0,
                'is_spam': True,
                'risk_level': 'dangerous',
                'top_keywords': ['urgent', 'click', 'verify', 'prize'],
                'keyword_scores': {'urgent': 0.8}
            }

            res = client.post("/emails/analyze-text",
                headers=auth_headers,
                json={
                    "subject": "URGENT: You won $1,000,000!",
                    "body": "Click here immediately to claim your prize. Verify your account now!",
                    "sender": "scammer@evil.com"
                }
            )
            assert res.status_code == 200
            data = res.json()
            assert data['risk_level'] == 'dangerous'
            assert data['spam_percent'] > 50

    def test_analyze_text_ham(self, client, auth_headers):
        """Email bình thường phải được đánh giá an toàn"""
        if not auth_headers:
            pytest.skip("Không có auth token")

        with patch('backend.app.routes.emails.get_predictor_instance') as mock_pred:
            mock_pred.return_value.predict.return_value = {
                'spam_score': 0.05,
                'spam_percent': 5.0,
                'is_spam': False,
                'risk_level': 'safe',
                'top_keywords': [],
                'keyword_scores': {}
            }

            res = client.post("/emails/analyze-text",
                headers=auth_headers,
                json={
                    "subject": "Team meeting tomorrow",
                    "body": "Hi everyone, just a reminder about our weekly sync at 10am.",
                    "sender": "manager@company.com"
                }
            )
            assert res.status_code == 200
            assert res.json()['risk_level'] == 'safe'

    def test_get_history_unauthorized(self, client):
        """Lịch sử email không có token phải bị từ chối"""
        res = client.get("/emails/history")
        assert res.status_code == 401

    def test_get_stats_unauthorized(self, client):
        """/emails/stats không có token phải bị từ chối"""
        res = client.get("/emails/stats")
        assert res.status_code == 401


# ========================
# TEST: BLACKLIST/WHITELIST
# ========================

class TestLists:

    def test_get_blacklist_unauthorized(self, client):
        res = client.get("/blacklist")
        assert res.status_code == 401

    def test_get_whitelist_unauthorized(self, client):
        res = client.get("/whitelist")
        assert res.status_code == 401


# ========================
# RUN
# ========================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])