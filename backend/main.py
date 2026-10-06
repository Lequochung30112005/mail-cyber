import logging
import sys
import os
from contextlib import asynccontextmanager

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import cấu hình và router

from config.logging_config import setup_logging
from database.models import create_tables
from core.scheduler import start_scheduler, stop_scheduler, get_scheduler_status
from app.routes import auth, email, lists, reports


# STARTUP / SHUTDOWN (Lifespan)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # === STARTUP ===
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("🚀 CyberMail Shield đang khởi động...")

    try:
        create_tables()
        logger.info("💾 Database đã sẵn sàng.")
    except Exception as e:
        logger.error(f"❌ Lỗi khởi tạo Database: {e}")

    try:

        start_scheduler(interval_minutes=15)
        logger.info("⏰ Scheduler đã sẵn sàng (chu kỳ 15 phút)")
    except Exception as e:
        logger.warning(f"⚠️ Scheduler warning: {e}")

    logger.info("✅ Server CyberMail Shield đã sẵn sàng!")
    yield

    # === SHUTDOWN ===
    stop_scheduler()
    logger.info("👋 Server đã dừng an toàn")


# FASTAPI APP CONFIG

app = FastAPI(
    title="🛡️ CyberMail Shield API",
    description="Hệ thống lọc Email thông minh (SVM + HHO)",
    version="1.1.0",
    lifespan=lifespan,
    # Chuyển docs vào /api để Nginx bắt được qua proxy_pass /api/
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# CORS CONFIG

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Cho phép tất cả trong môi trường dev/docker
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ROUTES - ĐỒNG BỘ TUYỆT ĐỐI VỚI FRONTEND & NGINX


app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])

app.include_router(email.router, prefix="/api/emails", tags=["Email Analysis"])
app.include_router(email.router, prefix="/api/email", tags=["Email Analysis"])

app.include_router(lists.router, prefix="/api/lists", tags=["Blacklist/Whitelist"])

app.include_router(reports.router, prefix="/api/reports", tags=["Reports Export"])


# HEALTH CHECK & SYSTEM

@app.get("/api/health", tags=["System"])
def health_check():
    """Dùng cho Docker Healthcheck và Nginx verify"""
    return {
        "status": "healthy",
        "scheduler": get_scheduler_status(),
        "database": "connected"
    }


@app.post("/api/scheduler/update", tags=["System"])
def update_scheduler(interval_minutes: int = 15):
    from core.scheduler import update_interval
    update_interval(interval_minutes)
    return {"message": f"Đã cập nhật chu kỳ quét: {interval_minutes} phút"}


# RUN SERVER

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
