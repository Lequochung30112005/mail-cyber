# ========================
# backend/app/routes/auth.py
# ========================
import bcrypt
import logging
import sys, os
from datetime import datetime, timedelta
from typing import Optional
import base64

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt

# Thư viện mã hóa RSA từ cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import settings
from backend.database.models import get_db, User
from backend.core.otp_service import create_otp_session, verify_otp

router = APIRouter(tags=["Authentication"])
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

# ==========================================================
# PERSISTENT RSA KEY PAIR (Lưu thẳng vào thư mục backend để không bị mất khi Docker rebuild)
# ==========================================================
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # backend/app/routes
APP_DIR = os.path.dirname(CURRENT_DIR)  # backend/app
BACKEND_DIR = os.path.dirname(APP_DIR)  # backend/ (Thư mục được Docker mount)

PRIVATE_KEY_PATH = os.path.join(BACKEND_DIR, "rsa_private.pem")
PUBLIC_KEY_PATH = os.path.join(BACKEND_DIR, "rsa_public.pem")

if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
    # Đọc lại cặp khóa đã lưu cố định trên ổ đĩa qua volume mount
    with open(PRIVATE_KEY_PATH, "rb") as f:
        _private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
        _public_pem = f.read()
else:
    # Sinh mới và lưu vào thư mục backend nếu chưa có
    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    _public_key = _private_key.public_key()

    _private_pem = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    _public_pem = _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(_private_pem)
    with open(PUBLIC_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(_public_pem)


def decrypt_rsa_password(encrypted_base64: str) -> str:
    """Giải mã mật khẩu nhận từ Frontend bằng Private Key cố định"""
    try:
        # --- IN LOG RA ĐỂ KIỂM TRA ---
        logger.info(
            f"--- [DEBUG RSA] Chuỗi nhận từ Frontend (độ dài {len(encrypted_base64)}): {encrypted_base64[:50]}...")

        decoded_data = base64.b64decode(encrypted_base64)
        logger.info(f"--- [DEBUG RSA] Base64 decode thành công, độ dài byte: {len(decoded_data)}")

        decrypted_message = _private_key.decrypt(
            decoded_data,
            padding.PKCS1v15()
        )
        return decrypted_message.decode('utf-8')
    except Exception as e:
        # IN LỖI CHI TIẾT RA TERMINAL
        logger.error(f"RSA Decryption Error Chi Tiết: {str(e)} | Dữ liệu gốc nhận được: {encrypted_base64}")
        raise HTTPException(status_code=400, detail=f"Lỗi giải mã: {str(e)}")


# --- SCHEMAS ---
class OTPVerifyRequest(BaseModel):
    email: str
    otp_code: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    role: str


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "staff"


class LoginRequest(BaseModel):
    username: str
    password: str


# --- HELPERS ---
def verify_password(plain: str, hashed: str) -> bool:
    if not hashed: return False
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])

    secret_key = "QuocHung_CyberMail_Shield_2026_SecureKey"
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=settings.ALGORITHM)


# --- DEPENDENCY: GET CURRENT USER ---
def get_current_user(auth: Optional[HTTPAuthorizationCredentials] = Depends(security),
                     db: Session = Depends(get_db)) -> User:
    if not auth:
        raise HTTPException(status_code=401, detail="Vui lòng đăng nhập")

    token = auth.credentials
    secret_key = "QuocHung_CyberMail_Shield_2026_SecureKey"
    try:
        payload = jwt.decode(token, secret_key, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token không hợp lệ")

        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=401, detail="Người dùng không tồn tại")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Phiên làm việc hết hạn")


# --- ENDPOINTS ---

@router.get("/public-key")
def get_public_key():
    """Endpoint cung cấp Public Key cho phía Frontend để mã hóa mật khẩu"""
    return {"public_key": _public_pem}


@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == req.username) | (User.email == req.email)).first():
        raise HTTPException(400, "Username hoặc Email đã tồn tại")

    new_user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        role=req.role.upper()
    )
    db.add(new_user)
    db.commit()
    return {"message": "Đăng ký thành công"}


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    # 1. Giải mã mật khẩu RSA từ client gửi lên thành password thô
    raw_password = decrypt_rsa_password(req.password)

    # 2. Kiểm tra thông tin user và xác thực mật khẩu qua bcrypt
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(raw_password, user.hashed_password):
        raise HTTPException(401, "Tài khoản hoặc mật khẩu không chính xác")

    create_otp_session(db, user.email)
    return {"message": "OTP đã được gửi", "email": user.email}


@router.post("/verify-otp", response_model=TokenResponse)
def verify_otp_endpoint(req: OTPVerifyRequest, db: Session = Depends(get_db)):
    if not verify_otp(db, req.email, req.otp_code):
        raise HTTPException(401, "Mã OTP không đúng hoặc đã hết hạn")

    user = db.query(User).filter(User.email == req.email).first()
    user.last_login = datetime.utcnow()
    db.commit()
    db.refresh(user)

    role_str = str(user.role.value if hasattr(user.role, 'value') else user.role)
    token = create_access_token({"sub": user.id, "role": role_str})

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "role": role_str
    }


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    role_str = str(current_user.role.value if hasattr(current_user.role, 'value') else current_user.role)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": role_str,
        "has_imap_config": True if current_user.imap_pass else False
    }
