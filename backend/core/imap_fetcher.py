import imaplib
import email
import logging
import re
import socket
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Optional
from datetime import datetime

import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

logger = logging.getLogger(__name__)


# --- HELPERS ---

def decode_mime_words(text: str) -> str:
    if not text: return ""
    try:
        parts = decode_header(text)
        decoded_parts = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded_parts.append(part.decode(charset or 'utf-8', errors='replace'))
            else:
                decoded_parts.append(str(part))
        return ' '.join(decoded_parts)
    except Exception:
        return text


def extract_text_from_email(msg) -> str:
    text_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    text = part.get_payload(decode=True).decode(charset, errors='replace')
                    text_parts.append(text)
                except:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or 'utf-8'
            text_parts.append(msg.get_payload(decode=True).decode(charset, errors='replace'))
        except:
            pass
    return ' '.join(text_parts)


def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]*|www\.[^\s<>"\'{}|\\^`\[\]]*', re.IGNORECASE)
    urls = url_pattern.findall(text)
    return list(set([re.sub(r'[.,;:!?)]+$', '', u) for u in urls if len(u) > 5]))


def fetch_emails(
        limit: int = 20,
        folder: str = "INBOX",
        unseen_only: bool = False,
        imap_server: str = None,
        imap_port: int = None,
        username: str = None,
        password: str = None
) -> list[dict]:
    imap_server = imap_server or settings.IMAP_SERVER
    imap_port = imap_port or settings.IMAP_PORT
    username = username or settings.IMAP_USERNAME
    password = password or settings.IMAP_PASSWORD

    if not username or not password:
        logger.error("❌ Thiếu cấu hình tài khoản Email để quét!")
        return []

    emails = []
    mail = None

    try:
        socket.setdefaulttimeout(30)
        logger.info(f"🔗 Đang kết nối tới {imap_server}...")

        mail = imaplib.IMAP4_SSL(imap_server, imap_port)
        mail.login(username, password)
        mail.select(folder)

        search_criteria = "(UNSEEN)" if unseen_only else "ALL"
        status, messages = mail.search(None, search_criteria)

        if (status != "OK" or not messages[0]) and unseen_only:
            logger.info("📭 Không có mail chưa đọc, tự động chuyển sang lấy mail cũ để demo...")
            status, messages = mail.search(None, "ALL")

        if status != "OK" or not messages[0]:
            logger.info("📭 Hộp thư hoàn toàn trống.")
            return []

        email_ids = messages[0].split()
        email_ids = email_ids[-limit:][::-1]  # Lấy 20 mail mới nhất

        logger.info(f"🔎 Đã tìm thấy {len(email_ids)} mail. Đang phân tích nội dung...")

        for eid in email_ids:
            try:
                status, msg_data = mail.fetch(eid, "(RFC822)")
                if status != "OK": continue

                msg = email.message_from_bytes(msg_data[0][1])
                body = extract_text_from_email(msg)

                try:
                    received_at = parsedate_to_datetime(msg.get("Date", ""))
                except:
                    received_at = datetime.now()

                emails.append({
                    "message_id": msg.get("Message-ID", f"gen_{eid.decode()}"),
                    "sender": decode_mime_words(msg.get("From", "")),
                    "subject": decode_mime_words(msg.get("Subject", "")),
                    "body": body,
                    "urls": extract_urls(body),
                    "received_at": received_at.replace(tzinfo=None),
                    "spf_pass": "spf=pass" in str(msg.get("Authentication-Results", "")).lower(),
                    "dkim_pass": "dkim=pass" in str(msg.get("Authentication-Results", "")).lower()
                })
            except Exception as e:
                logger.error(f"⚠️ Lỗi fetch mail ID {eid}: {e}")

        mail.logout()
        logger.info(f"✅ Đã xử lý xong {len(emails)} email.")

    except Exception as e:
        logger.error(f"❌ Lỗi kết nối IMAP: {e}")

    return emails
