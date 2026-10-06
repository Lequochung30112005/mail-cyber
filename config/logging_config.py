# ========================
# config/logging_config.py
# Cấu hình logging toàn hệ thống
# Ghi log ra file và console đồng thời
# ========================

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime

# Thư mục chứa log files
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


def setup_logging():
    """Khởi tạo logging cho toàn bộ ứng dụng"""

    # Format log
    LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # --- Handler 1: Console (chỉ hiện INFO trở lên) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # --- Handler 2: File xoay theo ngày ---
    today = datetime.now().strftime("%Y-%m-%d")
    file_handler = logging.handlers.TimedRotatingFileHandler(
        filename=LOG_DIR / f"cybermail_{today}.log",
        when="midnight",
        interval=1,
        backupCount=30,  # Giữ log 30 ngày
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # --- Handler 3: File riêng cho ERROR ---
    error_handler = logging.FileHandler(
        LOG_DIR / "errors.log", encoding="utf-8"
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    # Gắn handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Lấy logger theo tên module"""
    return logging.getLogger(name)