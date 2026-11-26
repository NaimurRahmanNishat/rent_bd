# backend/myproject/Dockerfile
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN mkdir -p /app/staticfiles /app/uploads /app/logs \
    && adduser --disabled-password --no-create-home appuser \
    && chown -R appuser:appuser /app/staticfiles /app/uploads /app/logs

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--no-control-socket", "myproject.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
