import pandas as pd
import io
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

# ReportLab cho PDF
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from backend.database.models import get_db, EmailLog, RiskLevel, User
from backend.app.routes.auth import get_current_user

router = APIRouter()


# --- HELPER FUNCTIONS ---
def extract_clean_text(html_content):
    """Lọc bỏ tag HTML an toàn và làm sạch dữ liệu cho Excel"""
    if not html_content or not isinstance(html_content, str):
        return ""
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        text = soup.get_text(separator=' ').strip()
        # Loại bỏ các ký tự điều khiển gây lỗi Excel
        return "".join(char for char in text if char.isprintable())
    except Exception:
        return str(html_content)


# --- CHỨC NĂNG 1: PREVIEW ---
@router.get("/preview")
async def get_report_preview(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        total_scanned = db.query(EmailLog).filter(EmailLog.user_id == current_user.id).count()
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)

        total_last_period = db.query(EmailLog).filter(
            EmailLog.user_id == current_user.id,
            EmailLog.analyzed_at < thirty_days_ago
        ).count()

        growth = 0
        if total_last_period > 0:
            growth = ((total_scanned - total_last_period) / total_last_period) * 100
        elif total_scanned > 0:
            growth = 100.0

        dangerous_emails = db.query(EmailLog).filter(
            EmailLog.user_id == current_user.id,
            EmailLog.risk_level == RiskLevel.DANGEROUS
        ).all()

        keyword_map = {}
        for email in dangerous_emails:
            if email.top_keywords:
                try:
                    words = json.loads(email.top_keywords) if isinstance(email.top_keywords,
                                                                         str) else email.top_keywords
                    if isinstance(words, list):
                        for word in words:
                            keyword_map[word] = keyword_map.get(word, 0) + 1
                except:
                    continue

        sorted_keywords = sorted(keyword_map.items(), key=lambda x: x[1], reverse=True)[:5]
        avg_spam = db.query(func.avg(EmailLog.spam_score)).filter(EmailLog.user_id == current_user.id).scalar() or 0

        return {
            "total_scanned": total_scanned,
            "growth_percent": round(growth, 1),
            "top_keywords": [k[0] for k in sorted_keywords] if sorted_keywords else ["None"],
            "average_spam": float(avg_spam)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Loi Preview: {str(e)}")


# --- CHỨC NĂNG 2: XUẤT DATASET EXCEL (BẢN FIX CHUẨN) ---
@router.get("/export-excel")
async def export_excel(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        logs = db.query(EmailLog).filter(EmailLog.user_id == current_user.id).all()

        dataset = []
        if not logs:
            # Tạo một dòng giả để file không bị lỗi khi mở
            dataset.append({"Thông báo": "Không có dữ liệu để hiển thị"})
        else:
            for log in logs:
                try:
                    # FIX 1: Dùng body_preview thay vì body
                    body_content = str(log.body_preview) if log.body_preview else ""

                    dataset.append({
                        "subject": str(log.subject) if log.subject else "(No Subject)",
                        "sender": str(log.sender) if log.sender else "Unknown",
                        "content_plain": extract_clean_text(body_content)[:1000],
                        "spam_score": float(log.spam_score or 0.0),
                        "phishing_score": float(log.phishing_score or 0.0),  # Tránh lỗi None
                        "url_count": body_content.count("http"),
                        "label": 1 if log.risk_level == RiskLevel.DANGEROUS else 0,
                        "analyzed_at": log.analyzed_at.strftime('%Y-%m-%d %H:%M:%S') if log.analyzed_at else ""
                    })
                except Exception as inner_e:
                    print(f"Lỗi dòng dữ liệu: {inner_e}")
                    continue

        df = pd.DataFrame(dataset)

        output = io.BytesIO()
        # FIX 2: Chuyển sang openpyxl cho nhẹ và ổn định trong Docker
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='CyberMail_Dataset')

        output.seek(0)

        # FIX 3: Đảm bảo tên file không có ký tự đặc biệt
        filename = f"CyberMail_Dataset_{current_user.id}.xlsx"

        return StreamingResponse(
            output,
            media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        print(f"CRITICAL EXPORT ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Loi xuat Excel: {str(e)}")
# --- CHỨC NĂNG 3: DOWNLOAD PDF ---
@router.get("/download-pdf")
async def download_pdf(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()

        # Header Báo cáo (Không dấu để tránh lỗi font)
        elements.append(Paragraph("BAO CAO HE THONG PHAN TICH EMAIL - CYBERMAIL", styles['Title']))
        elements.append(
            Paragraph(f"Tai khoan: {current_user.username} | Ngay xuat: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                      styles['Normal']))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceBefore=5, spaceAfter=15))

        # Truy vấn dữ liệu
        logs = db.query(EmailLog).filter(EmailLog.user_id == current_user.id).order_by(
            EmailLog.analyzed_at.desc()).limit(30).all()

        total_logs = len(logs)
        dangerous_count = sum(1 for log in logs if log.risk_level == RiskLevel.DANGEROUS)
        suspicious_count = sum(1 for log in logs if log.risk_level == RiskLevel.SUSPICIOUS)

        # Header bảng
        data = [["Nguoi gui", "Tieu de", "Spam %", "Phish %", "Ket qua"]]

        for log in logs:
            raw_spam = log.spam_score if log.spam_score is not None else 0
            display_spam = raw_spam if raw_spam > 1 else raw_spam * 100

            raw_phish = log.phishing_score if log.phishing_score is not None else 0
            display_phish = raw_phish if raw_phish > 1 else raw_phish * 100

            data.append([
                (str(log.sender)[:15] + "...") if log.sender and len(log.sender) > 15 else str(log.sender or "Unknown"),
                (str(log.subject)[:20] + "...") if log.subject and len(log.subject) > 20 else str(
                    log.subject or "(No Subject)"),
                f"{int(display_spam)}%",
                f"{int(display_phish)}%",
                str(log.risk_level.value).upper() if log.risk_level else "UNKNOWN"
            ])

        # Tạo bảng
        t = Table(data, colWidths=[120, 160, 55, 55, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161b22')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ]))
        elements.append(t)

        # Kết luận
        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        elements.append(Paragraph("KET LUAN HE THONG", styles['Heading3']))

        status_text = "CANH BAO" if dangerous_count > 0 else "AN TOAN"
        status_color = "red" if dangerous_count > 0 else "green"

        conclusion_body = f"""
        - Tong so email phan tich gan nhat: {total_logs}<br/>
        - So email Nguy hiem (Dangerous): {dangerous_count}<br/>
        - So email Nghi ngo (Suspicious): {suspicious_count}<br/>
        - Trang thai bao mat: <font color="{status_color}">{status_text}</font><br/><br/>
        <i>* Ghi chu: Ket qua duoc phan tich tu mo hinh AI. Vui long can nhac truoc khi click vao link.</i>
        """
        elements.append(Paragraph(conclusion_body, styles['Normal']))

        doc.build(elements)
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type='application/pdf',
            headers={'Content-Disposition': 'attachment; filename="CyberMail_Report.pdf"'}
        )
    except Exception as e:
        print(f"PDF ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Loi PDF: {str(e)}")