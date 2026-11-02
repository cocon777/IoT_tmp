FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# QUAN TRỌNG: Bắt buộc chạy đúng 1 worker (--workers 1) vì MQTT subscriber
# chạy chung tiến trình với FastAPI. Nếu chạy nhiều worker, mỗi worker sẽ
# tạo một MQTT subscriber riêng và xử lý trùng lặp từng bản tin telemetry/ack.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
