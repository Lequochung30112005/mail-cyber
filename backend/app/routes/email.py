import json
import logging
import re
from typing import Optional
from datetime import datetime
from email.utils import parseaddr

from fastapi import APIRouter, Depends, BackgroundTasks, Body, Query, HTTPException
from sqlalchemy.orm import Session

# Đảm bảo bạn đã import Whitelist và Blacklist từ models của dự án
from backend.database.models import get_db, EmailLog, RiskLevel, User, Blacklist, Whitelist
from backend.core.imap_fetcher import fetch_emails
from backend.core.url_scanner import scan_urls
from backend.app.routes.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Email Analysis"])


def extract_urls(text: str) -> list:
    if not text:
        return []
    url_pattern = re.compile(r'(?:https?://|www\.)[^\s<>"]+', re.IGNORECASE)
    return url_pattern.findall(text)


def is_trusted_sender(sender_str: str) -> bool:
    """Kiểm tra độ tin cậy của sender bằng cách tách chuẩn domain phía sau dấu @ để chống giả mạo hiển thị"""
    trusted_domains = {"accounts.google.com", "google.com", "microsoft.com", "github.com"}
    _, email_address = parseaddr(sender_str)

    if "@" in email_address:
        domain = email_address.split("@")[-1].lower()
        return domain in trusted_domains
    return False


@router.post("/config-imap")
async def update_imap_config(
        data: dict = Body(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    app_password = data.get("app_password")
    if not app_password or len(app_password) < 16:
        raise HTTPException(status_code=400, detail="App Password không hợp lệ (cần 16 ký tự)")

    current_user.imap_pass = app_password.replace(" ", "")
    current_user.imap_user = current_user.email
    db.commit()
    return {"message": "Cấu hình bảo mật email thành công!"}


def get_predictor_instance():
    try:
        from ai_engine.ai_predictor import get_predictor
        return get_predictor()
    except Exception as e:
        logger.error(f"❌ Không thể tải AI model: {e}")
        return None


def analyze_single_email(email_data: dict, db: Session, current_user: User):
    subject_text = email_data.get('subject', '') or ''
    body_text = email_data.get('body', '') or ''
    sender_text = email_data.get('sender', '') or ''

    # Lấy địa chỉ email chuẩn từ sender để so khớp Blacklist / Whitelist
    _, email_address = parseaddr(sender_text)
    target_email = email_address.lower() if email_address else sender_text.strip().lower()

    # ========================================================
    # 1. KIỂM TRA BLACKLIST: BỎ QUA HOÀN TOÀN NẾU NẰM TRONG DANH SÁCH ĐEN
    # ========================================================
    blacklisted = db.query(Blacklist).filter(
        Blacklist.value == target_email,
        Blacklist.type == "email"
    ).first()

    if blacklisted:
        logger.info(f"🚫 Email từ {sender_text} nằm trong Blacklist. Đã bỏ qua hoàn toàn!")
        return  # Thoát luôn, không lưu DB, không gọi AI

    # ========================================================
    # 2. KIỂM TRA WHITELIST: TIN TƯỞNG, GÁN AN TOÀN VÀ LƯU DB
    # ========================================================
    whitelisted = db.query(Whitelist).filter(
        Whitelist.value == target_email,
        Whitelist.type == "email"
    ).first()

    if whitelisted:
        logger.info(f"✅ Email từ {sender_text} nằm trong Whitelist. Đánh dấu an toàn!")
        ai_result = {
            'spam_percent': 0.0,
            'phishing_percent': 0.0,
            'risk_level': 'safe',
            'top_keywords': [],
            'details': {'reason': f"Được tin tưởng do nằm trong Whitelist"}
        }
        url_result = {'total': 0, 'malicious': 0, 'details': []}
        final_risk = 'safe'
    else:
        # ========================================================
        # 3. XỬ LÝ BÌNH THƯỜNG (AI + URL SCAN) CHO CÁC EMAIL KHÁC
        # ========================================================
        predictor = get_predictor_instance()
        ai_result = {'spam_percent': 0.0, 'phishing_percent': 0.0, 'risk_level': 'safe', 'top_keywords': [],
                     'details': {}}

        urls = email_data.get('urls') or extract_urls(body_text)

        if predictor:
            ai_result = predictor.predict(
                email_text=body_text,
                subject=subject_text,
                urls=urls
            )

        url_result = email_data.get('url_scan_result')
        if not url_result:
            import os
            VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
            url_result = scan_urls(db, urls, use_virustotal=bool(VT_API_KEY))

        final_risk = str(ai_result.get('risk_level', 'safe')).lower()

        if is_trusted_sender(sender_text):
            final_risk = 'safe'
        else:
            if not subject_text.strip():
                if final_risk == 'safe':
                    final_risk = 'suspicious'

            if url_result.get('malicious', 0) > 0 or email_data.get("vt_malicious_detected", False):
                final_risk = 'dangerous'

    # Lấy tỷ lệ phần trăm và chuẩn hóa sang dạng thập phân (0.0 - 1.0) để lưu DB
    raw_spam = ai_result.get('spam_percent', 0.0)
    raw_phish = ai_result.get('phishing_percent', 0.0)

    s_score = float(raw_spam) / 100.0 if float(raw_spam) > 1.0 else float(raw_spam)
    p_score = float(raw_phish) / 100.0 if float(raw_phish) > 1.0 else float(raw_phish)

    existing = db.query(EmailLog).filter(
        EmailLog.message_id == email_data.get('message_id'),
        EmailLog.user_id == current_user.id
    ).first()

    serialized_url_details = json.dumps(url_result.get('details', []))

    if not existing:
        log = EmailLog(
            message_id=email_data.get('message_id', ''),
            sender=sender_text[:255],
            subject=subject_text[:500],
            body_preview=body_text,
            spam_score=s_score,
            phishing_score=p_score,
            risk_level=RiskLevel(final_risk),
            top_keywords=json.dumps(ai_result.get('top_keywords', [])),
            urls_found=url_result.get('total', 0),
            urls_malicious=url_result.get('malicious', 0),
            url_details=serialized_url_details,
            user_id=current_user.id,
            analyzed_at=datetime.utcnow()
        )
        db.add(log)
        db.commit()
    else:
        existing.spam_score = s_score
        existing.phishing_score = p_score
        existing.risk_level = RiskLevel(final_risk)
        existing.url_details = serialized_url_details
        existing.urls_found = url_result.get('total', 0)
        existing.urls_malicious = url_result.get('malicious', 0)
        db.commit()


@router.post("/fetch-and-analyze")
async def fetch_and_analyze(
        req: dict = Body(None),
        background_tasks: BackgroundTasks = BackgroundTasks(),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if not current_user.imap_pass:
        raise HTTPException(status_code=400, detail="Vui lòng cấu hình App Password trước!")

    limit = req.get("limit", 20) if req else 20
    unseen = req.get("unseen_only", True) if req else True

    def _task():
        with next(get_db()) as session:
            try:
                emails = fetch_emails(
                    limit=limit,
                    unseen_only=unseen,
                    username=current_user.imap_user,
                    password=current_user.imap_pass
                )
                for e in emails:
                    analyze_single_email(e, session, current_user)
            except Exception as e:
                logger.error(f"❌ Lỗi quét email: {e}")

    background_tasks.add_task(_task)
    return {"message": "Đang quét email..."}


@router.get("/history")
def get_history(
        page: int = 1,
        limit: int = 12,
        search: Optional[str] = None,
        risk_level: Optional[str] = None,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    query = db.query(EmailLog).filter(EmailLog.user_id == current_user.id).order_by(EmailLog.analyzed_at.desc())

    if search:
        query = query.filter(EmailLog.sender.contains(search) | EmailLog.subject.contains(search))

    if risk_level and risk_level.strip():
        normalized_risk = risk_level.strip().lower()
        query = query.filter(EmailLog.risk_level == RiskLevel(normalized_risk))

    total = query.count()
    logs = query.offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "data": [
            {
                "id": log.id,
                "sender": log.sender,
                "subject": log.subject,
                "risk_level": log.risk_level.value,
                "spam_score": round((log.spam_score or 0.0) * 100, 1),
                "phishing_score": round((log.phishing_score or 0.0) * 100, 1),
                "analyzed_at": log.analyzed_at,
                "top_keywords": json.loads(log.top_keywords) if log.top_keywords else []
            } for log in logs
        ]
    }


@router.get("/stats")
def get_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    base_query = db.query(EmailLog).filter(EmailLog.user_id == current_user.id)
    return {
        "summary": {
            "total": base_query.count(),
            "safe": base_query.filter(EmailLog.risk_level == RiskLevel.SAFE).count(),
            "suspicious": base_query.filter(EmailLog.risk_level == RiskLevel.SUSPICIOUS).count(),
            "dangerous": base_query.filter(EmailLog.risk_level == RiskLevel.DANGEROUS).count()
        }
    }


@router.get("/{email_id}")
def get_email_detail(email_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    email_log = db.query(EmailLog).filter(EmailLog.id == email_id, EmailLog.user_id == current_user.id).first()
    if not email_log:
        raise HTTPException(status_code=404, detail="Không tìm thấy email")

    spam_pct = (email_log.spam_score or 0.0) * 100
    phish_pct = (email_log.phishing_score or 0.0) * 100
    total_score = (spam_pct * 0.5) + (phish_pct * 0.5)

    if total_score >= 45.0 or (email_log.urls_malicious or 0) > 0:
        dynamic_risk = "dangerous"
    elif total_score >= 15.0 or spam_pct >= 25.0 or phish_pct >= 25.0 or not email_log.subject:
        dynamic_risk = "suspicious"
    else:
        dynamic_risk = email_log.risk_level.value

    return {
        "id": email_log.id,
        "sender": email_log.sender,
        "subject": email_log.subject,
        "body": email_log.body_preview,
        "spam_score": round(spam_pct, 1),
        "phishing_score": round(phish_pct, 1),
        "risk_level": dynamic_risk,
        "top_keywords": json.loads(email_log.top_keywords) if email_log.top_keywords else [],
        "urls_found": email_log.urls_found or 0,
        "urls_malicious": email_log.urls_malicious or 0,
        "url_details": json.loads(email_log.url_details) if email_log.url_details else []
    }


@router.post("/predict-spam")
async def predict_manual_email(
        data: dict = Body(...),
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
):
    raw_subject = data.get("subject", "")
    raw_body = data.get("body", "")

    subject = raw_subject.strip()
    body = raw_body.strip()

    warnings = []
    penalty_score = 0

    if not subject:
        penalty_score += 15
        warnings.append("⚠️ Bạn chưa nhập tiêu đề email (Subject). Hệ thống đã cộng thêm điểm rủi ro nghi vấn!")
        subject = "(Không có tiêu đề)"

    if not body:
        penalty_score += 35
        warnings.append(
            "⚠️ Nội dung email (Body) đang trống. Vui lòng nhập nội dung để kết quả phân tích chính xác nhất!")
        body = "(Không có nội dung)"

    urls = data.get("urls") or extract_urls(body)

    predictor = get_predictor_instance()
    if not predictor:
        logger.error("❌ Không thể khởi tạo predictor trong predict-spam!")
        return {
            "spam_score": float(penalty_score),
            "phishing_score": float(penalty_score),
            "risk_level": "suspicious" if penalty_score > 0 else "safe",
            "email_category": "Suspicious (Nghi vấn do thiếu thông tin)" if penalty_score > 0 else "Clean / Normal (Bình thường)",
            "warnings": warnings,
            "top_keywords": [],
            "url_details": [],
            "details": {},
            "explanation": {
                "summary": "Nghi vấn do thiếu mô hình AI",
                "reasons": warnings if warnings else ["Không thể tải mô hình phân tích."]
            }
        }

    ai_result = predictor.predict(email_text=body, subject=subject, urls=urls)

    import os
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    url_result = scan_urls(db, urls, use_virustotal=bool(VT_API_KEY))

    spam_pct = min(100.0, float(ai_result.get("spam_percent", 0)) + penalty_score)
    phish_pct = min(100.0, float(ai_result.get("phishing_percent", 0)) + (penalty_score / 2))

    final_risk = str(ai_result.get("risk_level", "safe")).lower()

    if url_result.get("malicious", 0) > 0:
        final_risk = "dangerous"
    elif penalty_score > 0 and final_risk == "safe":
        final_risk = "suspicious"

    has_malicious_url = url_result.get("malicious", 0) > 0

    if has_malicious_url or (phish_pct >= 50 and spam_pct >= 50):
        email_category = "Spam & Phishing (Vừa rác vừa lừa đảo nguy hiểm)"
        final_risk = "dangerous"
    elif phish_pct >= 50 or (phish_pct >= spam_pct and phish_pct >= 30):
        email_category = "Phishing (Lừa đảo giả mạo)"
        if final_risk == "safe":
            final_risk = "suspicious" if phish_pct < 70 else "dangerous"
    elif spam_pct >= 50:
        email_category = "Spam (Thư rác quảng cáo)"
        if final_risk == "safe":
            final_risk = "suspicious"
    elif phish_pct > 0 or spam_pct > 0 or penalty_score > 0:
        email_category = "Suspicious (Nghi vấn rủi ro)"
        if final_risk == "safe":
            final_risk = "suspicious"
    else:
        email_category = "Clean / Normal (Bình thường)"

    explanation_reasons = []

    if ai_result.get('top_keywords'):
        keywords_str = ", ".join(ai_result.get('top_keywords'))
        explanation_reasons.append(f"AI phát hiện các từ khóa nhạy cảm: [{keywords_str}]")

    if url_result.get("malicious", 0) > 0:
        explanation_reasons.append(
            f"Cảnh báo nguy hiểm: Phát hiện {url_result.get('malicious')} liên kết (URL) độc hại!")
    elif url_result.get("total", 0) > 0:
        explanation_reasons.append(f"Tìm thấy {url_result.get('total')} đường dẫn trong nội dung email.")

    if penalty_score > 0:
        explanation_reasons.extend(warnings)

    if not explanation_reasons:
        if final_risk == "dangerous" or spam_pct >= 50 or phish_pct >= 50:
            explanation_reasons.append(
                f"Mô hình AI phát hiện cấu trúc văn bản có đặc trưng nguy hiểm cao (Spam: {spam_pct}%, Phishing: {phish_pct}%).")
        elif final_risk == "suspicious" or spam_pct >= 20 or phish_pct >= 20:
            explanation_reasons.append(
                f"Mô hình AI ghi nhận cấu trúc văn bản có dấu hiệu nghi vấn (Spam: {spam_pct}%, Phishing: {phish_pct}%).")
        else:
            explanation_reasons.append("Nội dung sạch, cấu trúc bình thường, không phát hiện dấu hiệu bất thường.")

    return {
        "spam_score": round(spam_pct, 1),
        "phishing_score": round(phish_pct, 1),
        "risk_level": final_risk,
        "email_category": email_category,
        "warnings": warnings,
        "top_keywords": ai_result.get("top_keywords", []),
        "url_details": url_result.get("details", []),
        "details": ai_result.get("details", {}),
        "explanation": {
            "summary": email_category,
            "reasons": explanation_reasons
        }
    }
