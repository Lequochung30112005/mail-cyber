# ========================
# config/settings.py
# Quản lý toàn bộ cấu hình từ file .env
# ========================

from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # --- Database ---
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_NAME: str = "cybermail_shield"
    DB_USER: str = "root"
    DB_PASSWORD: str = ""

    # --- JWT ---
    SECRET_KEY: str = "changethis"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Mail gửi OTP ---
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = ""
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"

    # --- IMAP đọc mail ---
    IMAP_SERVER: str = "imap.gmail.com"
    IMAP_PORT: int = 993
    IMAP_USERNAME: str = ""
    IMAP_PASSWORD: str = ""

    # --- VirusTotal ---
    VIRUSTOTAL_API_KEY: str = ""

    # --- AI Model ---
    # config/settings.py sửa lại đoạn này:

    # --- AI Model ---

    SPAM_MODEL: str = "ai_engine/models/spam_model.pkl"
    SPAM_VECT: str = "ai_engine/models/spam_vectorizer.pkl"

    HHO_MODEL: str = "ai_engine/models/svm_hho_model.pkl"
    HHO_VECT: str = "ai_engine/models/tfidf_vectorizer.pkl"

    PHISH_MODEL: str = "ai_engine/models/url_phishing_model.pkl"
    PHISH_SCALER: str = "ai_engine/models/url_scaler.pkl"

    SPAM_THRESHOLD: float = 0.6

    # --- App ---
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = True

    class Config:
        env_file = str(BASE_DIR / ".env")
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """Cache settings để không load lại nhiều lần"""
    return Settings()


settings = get_settings()
