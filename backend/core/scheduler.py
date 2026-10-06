import logging
import re
import time
import asyncio
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

# Singleton scheduler
_scheduler = AsyncIOScheduler()
_current_interval_minutes = 1

# Bộ nhớ tạm kiểm soát Rate Limiter cho VirusTotal
_vt_request_timestamps = []
MAX_VT_REQUESTS_PER_MINUTE = 4

# Khóa Semaphore giới hạn tối đa bao nhiêu user được quét song song cùng lúc (tránh tràn RAM/IMAP connection)
MAX_CONCURRENT_USERS = 5


def can_make_vt_request() -> bool:
    """Kiểm tra hạn mức gọi API trong vòng 60 giây qua"""
    global _vt_request_timestamps
    now = time.time()
    _vt_request_timestamps = [t for t in _vt_request_timestamps if now - t < 60]
    return len(_vt_request_timestamps) < MAX_VT_REQUESTS_PER_MINUTE


def record_vt_request():
    """Ghi nhận mốc thời gian gọi API"""
    global _vt_request_timestamps
    _vt_request_timestamps.append(time.time())


def extract_urls_from_text(text: str) -> list:
    """Trích xuất và làm sạch triệt để danh sách URL từ nội dung email"""
    if not text:
        return []

    url_pattern = re.compile(r'(?:https?://|www\.)[^\s<>"]+', re.IGNORECASE)
    found = url_pattern.findall(text)

    cleaned = []
    for url in found:
        url = url.rstrip('">.,;)]}>')
        if "google.com/search" in url:
            continue
        if url.startswith("www."):
            url = "https://" + url
        if url and url not in cleaned:
            cleaned.append(url)
    return cleaned


async def _scan_single_user(user, semaphore):
    """Hàm xử lý quét cho 1 user độc lập, chạy bất đồng bộ với Semaphore kiểm soát tải"""
    async with semaphore:
        try:
            from backend.database.models import SessionLocal
            from backend.core.imap_fetcher import fetch_emails
            from backend.app.routes.email import analyze_single_email
            from backend.core.url_scanner import scan_urls
            import os

            VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

            # Mỗi user mở một phiên database riêng để tránh xung đột thread/session
            db = SessionLocal()
            try:
                # Sử dụng to_thread nếu fetch_emails là hàm đồng bộ (blocking I/O)
                # Giúp không block vòng lặp sự kiện chính của Asyncio
                emails = await asyncio.to_thread(
                    fetch_emails,
                    limit=20,
                    unseen_only=True,
                    username=user.imap_user,
                    password=user.imap_pass
                )

                scanned_count = 0
                for e in emails:
                    body = e.get("body", "")
                    urls = extract_urls_from_text(body)

                    # scan_urls có thể chạy đồng bộ hoặc async tùy cấu trúc code hiện tại của bạn
                    url_scan_result = await asyncio.to_thread(
                        scan_urls, db, urls, use_virustotal=bool(VT_API_KEY)
                    )

                    e["urls"] = urls
                    e["url_scan_result"] = url_scan_result
                    e["vt_malicious_detected"] = (url_scan_result.get("malicious", 0) > 0)

                    await asyncio.to_thread(analyze_single_email, e, db, user)
                    scanned_count += 1

                logger.info(f"✔️ Đã quét xong cho user: {user.imap_user} ({scanned_count} email mới)")
            finally:
                db.close()
        except Exception as user_ex:
            logger.warning(f"⚠️ Lỗi khi quét user {user.imap_user}: {user_ex}")


async def _auto_scan_job():
    """Hàm chạy ngầm quét email đồng thời cho toàn bộ danh sách user"""
    logger.info(f"🤖 Auto-scan bắt đầu lúc {datetime.now().strftime('%H:%M:%S')}")

    try:
        from backend.database.models import SessionLocal, User
        db = SessionLocal()

        try:
            users = db.query(User).filter(User.imap_pass != None).all()
        finally:
            db.close()

        if not users:
            logger.info("ℹ️ Không có user nào cấu hình IMAP để quét.")
            return

        # Tạo Semaphore giới hạn tối đa 5 user chạy đồng thời cùng lúc
        # (tránh làm sập server vì mở quá nhiều kết nối IMAP/DB cùng lúc)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_USERS)

        # Tạo các tác vụ bất đồng bộ cho toàn bộ user
        tasks = [_scan_single_user(user, semaphore) for user in users]

        # Chạy song song tất cả các task và chờ hoàn tất
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"✅ Auto-scan hoàn tất cho tổng số {len(users)} user.")
    except Exception as ex:
        logger.error(f"❌ Lỗi hệ thống trong auto-scan job: {ex}")


# --- QUẢN LÝ SCHEDULER & FASTAPI LIFESPAN ---

def start_scheduler(interval_minutes: int = 1):
    """Khởi động scheduler"""
    global _current_interval_minutes
    _current_interval_minutes = interval_minutes

    if _scheduler.running:
        _scheduler.remove_all_jobs()

    _scheduler.add_job(
        _auto_scan_job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="auto_email_scan",
        name="Quét Email Tự Động Song Song",
        replace_existing=True,
        next_run_time=datetime.now() + timedelta(seconds=5)
    )

    if not _scheduler.running:
        _scheduler.start()
    logger.info(f"⏰ Scheduler đang chạy: quét song song định kỳ mỗi {interval_minutes} phút")


def stop_scheduler():
    """Dừng scheduler"""
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("⏹ Scheduler đã dừng")


def update_interval(new_interval_minutes: int):
    """Cập nhật thời gian quét chu kỳ mới"""
    start_scheduler(new_interval_minutes)


def get_scheduler_status() -> dict:
    """Lấy trạng thái scheduler hiện tại phục vụ cho API Health Check"""
    try:
        jobs = _scheduler.get_jobs()
        job_info = [{"id": j.id, "name": j.name, "next_run": str(j.next_run_time)} for j in jobs]
        return {
            "running": _scheduler.running,
            "interval_minutes": _current_interval_minutes,
            "jobs": job_info
        }
    except Exception as e:
        return {"running": False, "error": str(e)}
