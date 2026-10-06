FROM python:3.11-slim

WORKDIR /app


RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*


COPY backend/requirements.txt ./backend/requirements.txt
COPY ai_engine/requirements_ai.txt ./ai_engine/requirements_ai.txt


RUN pip install --no-cache-dir -r backend/requirements.txt
RUN pip install --no-cache-dir -r ai_engine/requirements_ai.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]