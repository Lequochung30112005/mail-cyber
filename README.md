# 🛡 CyberMail Shield

### Hệ thống phân loại email

---

## Giới thiệu

**CyberMail Shield** là hệ thống bảo mật email thông minh, giúp doanh nghiệp vừa và nhỏ phát hiện và ngăn chặn các mối
đe dọa từ email (Spam, Phishing, Malware) thông qua kết hợp **AI/ML** và **hệ thống luật bảo mật**.

### Vấn đề giải quyết

- 91% tấn công mạng bắt đầu từ email phishing
- Doanh nghiệp SME thiếu công cụ bảo mật email chuyên nghiệp
- Nhân viên không đủ kỹ năng nhận biết email lừa đảo

Mục tiêu phát triển :
Xuất file XLSX cập nhật các data mới làm bo dataset mới lấy làm nguồn nguyên liệu cho việc huấn luyện mô hình.
=> Cải thiện việc thiếu dữ liệu trong thời đại kỹ thuật số

- => Dự đoán nhu cầu khách hàng trong tương lai
- => tạo ra mô hình tự động hoá bỏ qua việc tìm kiếm dữ liệu , tự thu nhận các dataset ít bị nhiễu và dễ dàng xử lí để
  đưa vào mô hình

## ✨ Tính năng chính

| Tính năng           | Mô tả                                   |
|---------------------|-----------------------------------------|
| **AI Detection**    | SVM + Bilstm tối ưu, độ chính xác >95%     |
| **URL Scanner**     | Blacklist DB + VirusTotal API real-time |
| **IMAP Auto-fetch** | Tự động kéo email Gmail/Outlook         |
| **2FA OTP**         | Xác thực 2 lớp bảo vệ tài khoản         |
| **Explain AI**      | Hiển thị từ khóa gây ra cảnh báo        |
| **Dashboard**       | Biểu đồ thống kê trực quan              |
| **Export**          | Xuất báo cáo PDF và Excel               |
| **Scheduler**       | Quét email tự động định kỳ              |
| **Docker**          | Deploy 1 lệnh với Docker Compose        |

---

## Kiến trúc hệ thống

```
                    ┌─────────────────────────────────┐
                    │         FRONTEND (React)         │
                    │  Login → OTP → Dashboard → CRUD  │
                    └──────────────┬──────────────────┘
                                   │ REST API (JWT)
                    ┌──────────────▼──────────────────┐
                    │         BACKEND (FastAPI)         │
                    │                                   │
              ┌─────┤  Auth  │  Email  │  Lists  │ PDF ├─────┐
              │     └────────────────────────────────┘      │
              │                                              │
    ┌─────────▼──────────┐                    ┌─────────────▼────────┐
    │    AI Engine        │                    │   External Services  │
    │  SVM + HHO + TFIDF
     Bilstm│                                   │  VirusTotal API      │
    │  Explain AI         │                    │  IMAP (Gmail/Outlook)│
    └─────────────────────┘                    │  SMTP (OTP sender)   │
                                               └──────────────────────┘
                    ┌──────────────────────────────────┐
                    │         DATABASE (MySQL)          │
                    │  Users│EmailLogs│Blacklist│OTP   │
                    └──────────────────────────────────┘
```

---

## 🚀 Hướng dẫn cài đặt

### Yêu cầu

- Python 3.11+
- Node.js 18+
- MySQL 8.0+
- Docker & Docker Compose (tùy chọn)

---

### 🐳 Cách 1: Docker (Khuyến nghị — nhanh nhất)

#1. Khởi động tất cả bằng 1 lệnh
docker-compose up --build

# 2. Mở trình duyệt

# Frontend: http://localhost:5000

# API Docs: http://localhost:8000/api/docs -

```

---



## 🔧 Cấu hình .env

```env
# Database
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=cybermail_shield

# JWT
SECRET_KEY=your-super-secret-key-here

# Gmail SMTP (gửi OTP)
MAIL_USERNAME=your@gmail.com
MAIL_PASSWORD=your-app-password    # Google App Password

# IMAP (đọc email doanh nghiệp)
IMAP_USERNAME=company@gmail.com
IMAP_PASSWORD=your-app-password

# VirusTotal (miễn phí tại virustotal.com)
VIRUSTOTAL_API_KEY=your-api-key
```

> 💡 **Lấy Google App Password**: Gmail → Settings → Security → 2FA → App Passwords

---


---

## 📁 Cấu trúc thư mục

```
CyberMail_Shield/
├── data/
│   └── combined_data.csv          # Dataset Enron Spam
├── ai_engine/
│   ├── models/                    # Model .pkl sau khi train
│   ├── preprocessing.py           # Làm sạch dữ liệu
│   ├── train_hho_svm.py           # Train SVM + HHO
│   ├── ai_predictor.py            # Predict + Explain AI
│   └── requirements_ai.txt
├── backend/
│   ├── app/routes/
│   │   ├── auth.py                # Login, OTP, JWT
│   │   ├── emails.py              # Phân tích email
│   │   ├── lists.py               # Blacklist/Whitelist CRUD
│   │   └── reports.py             # Xuất PDF/Excel
│   ├── core/
│   │   ├── imap_fetcher.py        # Kéo email IMAP
│   │   ├── otp_service.py         # Gửi OTP
│   │   ├── url_scanner.py         # Quét URL + VirusTotal
│   │   └── scheduler.py           # Auto-scan định kỳ
│   ├── config/
│   │   ├── settings.py            # Cấu hình từ .env
│   │   └── logging_config.py      # Logging
│   ├── database/
│   │   └── models.py              # SQLAlchemy models
│   ├── logs/                      # Log files
│   ├── requirements.txt
│   ├── Dockerfile
│   └── main.py                    # FastAPI entry point
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx      # Đăng nhập + OTP
│   │   │   ├── Dashboard.jsx      # Dashboard chính
│   │   │   └── BlacklistPage.jsx  # Quản lý Lists
│   │   ├── services/api.js        # API calls
│   │   └── App.jsx                # Router
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
├── tests/
│   ├── test_ai_engine.py          # Test AI + preprocessing
│   └── test_api.py                # Test API endpoints
├── docs/                          # ERD, UseCase, Architecture
├── docker-compose.yml
├── .env.example
└── README.md

## 📄 License
MIT License — Dự án nhóm 
