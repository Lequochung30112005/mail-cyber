# ========================
# database/models.py
# Định nghĩa toàn bộ bảng CSDL bằng SQLAlchemy ORM - BẢN CẬP NHẬT 2026
# ========================

from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, Text, Enum, ForeignKey, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

# Base class cho tất cả models
Base = declarative_base()


# ========================
# ENUMS
# ========================

class RiskLevel(str, enum.Enum):
    SAFE = "safe"  # Xanh - An toàn
    SUSPICIOUS = "suspicious"  # Vàng - Nghi ngờ
    DANGEROUS = "dangerous"  # Đỏ - Nguy hiểm


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    STAFF = "staff"


# ========================
# TABLE: Users
# ========================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.STAFF)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Cấu hình IMAP
    imap_server = Column(String(255), default="imap.gmail.com")
    imap_user = Column(String(255), nullable=True)
    imap_pass = Column(String(255), nullable=True)  # Mật khẩu ứng dụng đã mã hóa

    # Relationship - Cascade xóa user thì xóa luôn log liên quan
    email_logs = relationship("EmailLog", back_populates="analyzed_by_user", cascade="all, delete-orphan")


# ========================
# TABLE: EmailLogs — Lịch sử phân tích email
# ========================
class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(255), unique=True, nullable=True)
    sender = Column(String(255), nullable=False, index=True)  # Thêm Index để tìm kiếm nhanh
    subject = Column(String(500), nullable=True)
    body_preview = Column(Text, nullable=True)

    # --- KẾT QUẢ AI (ĐÃ CẬP NHẬT) ---
    spam_score = Column(Float, default=0.0)  # 0.0 - 1.0 (hoặc 0-100 tùy logic)
    phishing_score = Column(Float, default=0.0)  # MỚI: Điểm lừa đảo (Fix lỗi xuất PDF)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.SAFE)
    top_keywords = Column(Text, nullable=True)  # JSON string

    # Kết quả URL scan
    urls_found = Column(Integer, default=0)
    urls_malicious = Column(Integer, default=0)
    url_details = Column(Text, nullable=True)  # JSON string

    # Kết quả Header
    spf_pass = Column(Boolean, nullable=True)
    dkim_pass = Column(Boolean, nullable=True)

    # Metadata
    received_at = Column(DateTime, nullable=True)
    analyzed_at = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)

    # Relationship
    analyzed_by_user = relationship("User", back_populates="email_logs")


# ========================
# TABLE: Blacklist / Whitelist
# ========================
class Blacklist(Base):
    __tablename__ = "blacklist"
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(500), unique=True, nullable=False, index=True)
    type = Column(String(20), nullable=False)  # "domain", "ip", "email"
    reason = Column(String(255), nullable=True)
    added_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow)


class Whitelist(Base):
    __tablename__ = "whitelist"
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(500), unique=True, nullable=False, index=True)
    type = Column(String(20), nullable=False)
    reason = Column(String(255), nullable=True)
    added_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow)


# ========================
# TABLE: OTP Sessions
# ========================
class OTPSession(Base):
    __tablename__ = "otp_sessions"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), nullable=False, index=True)
    otp_code = Column(String(6), nullable=False)
    is_used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ========================
# TABLE: ScanSchedule
# ========================
class ScanSchedule(Base):
    __tablename__ = "scan_schedules"
    id = Column(Integer, primary_key=True, index=True)
    interval_minutes = Column(Integer, default=15)
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)


# ========================
# DATABASE CONNECTION
# ========================
DATABASE_URL = (
    f"mysql+pymysql://{settings.DB_USER}:{settings.DB_PASSWORD}"
    f"@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables updated/created successfully!")