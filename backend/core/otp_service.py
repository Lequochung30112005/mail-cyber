import random
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.orm import Session

import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings
from backend.database.models import OTPSession

logger = logging.getLogger(__name__)

OTP_EXPIRE_MINUTES = 5


def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def send_otp_email(to_email: str, otp_code: str, username: str = "") -> bool:
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[CyberMail Shield] Mã OTP của bạn: {otp_code}"
        msg['From'] = settings.MAIL_FROM
        msg['To'] = to_email

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px;">
          <div style="max-width:480px; margin:auto; background:#fff; border-radius:10px;
                      box-shadow:0 2px 8px rgba(0,0,0,0.1); padding:30px;">
            <div style="text-align:center; margin-bottom:20px;">
              <h2 style="color:#1a1a2e; margin:0;">🛡️ CyberMail Shield</h2>
              <p style="color:#666; font-size:13px;">Hệ thống Bảo mật Email Thông minh</p>
            </div>
            <hr style="border:none; border-top:1px solid #eee;">
            <p style="color:#333;">Xin chào <strong>{username or to_email}</strong>,</p>
            <p style="color:#333;">Mã OTP xác thực đăng nhập của bạn là:</p>
            <div style="text-align:center; margin:25px 0;">
              <span style="font-size:36px; font-weight:bold; letter-spacing:10px;
                           color:#e94560; background:#fff0f3; padding:15px 30px;
                           border-radius:8px; border:2px dashed #e94560;">
                {otp_code}
              </span>
            </div>
            <p style="color:#666; font-size:13px; text-align:center;">
              ⏰ Mã có hiệu lực trong <strong>{OTP_EXPIRE_MINUTES} phút</strong>
            </p>
            <div style="background:#fff3cd; border:1px solid #ffc107; border-radius:6px;
                        padding:12px; margin-top:20px;">
              <p style="margin:0; color:#856404; font-size:13px;">
                ⚠️ Không chia sẻ mã này với bất kỳ ai. 
              </p>
            </div>
          </div>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(settings.MAIL_SERVER, settings.MAIL_PORT) as server:
            server.starttls()
            server.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)
            server.sendmail(settings.MAIL_FROM, to_email, msg.as_string())

        logger.info(f"✅ Đã gửi OTP đến {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ Lỗi gửi OTP đến {to_email}: {e}")
        return False


def create_otp_session(db: Session, email: str) -> str:
    db.query(OTPSession).filter(OTPSession.email == email).delete()

    otp_code = generate_otp()

    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)

    session = OTPSession(
        email=email,
        otp_code=otp_code,
        is_used=False,
        expires_at=expires_at
    )
    db.add(session)
    db.commit()

    send_otp_email(email, otp_code)
    return otp_code


def verify_otp(db: Session, email: str, otp_code: str) -> bool:
    now = datetime.utcnow()

    otp_str = str(otp_code).strip()

    session = db.query(OTPSession).filter(
        OTPSession.email == email,
        OTPSession.is_used == False
    ).order_by(OTPSession.created_at.desc()).first()

    # 5. LOG ĐỂ DEBUG (Quan trọng)
    if session:
        logger.info(f"🔍 Đang check OTP cho {email}")
        logger.info(f"DB Code: {session.otp_code} | User Code: {otp_str}")
        logger.info(f"Giờ hiện tại (UTC): {now} | Giờ hết hạn: {session.expires_at}")

    # 6. KIỂM TRA ĐIỀU KIỆN
    if not session or session.otp_code != otp_str:
        logger.warning(f"❌ OTP không khớp cho {email}")
        return False

    if session.expires_at < now:
        logger.warning(f"⏰ OTP đã hết hạn cho {email}")

        return False

    session.is_used = True
    db.commit()
    logger.info(f"✅ OTP xác thực thành công!")
    return True
