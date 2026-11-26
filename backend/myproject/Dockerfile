# backend/myproject/Dockerfile
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --chown=appuser:appuser requirements.txt /app/

RUN adduser --disabled-password --no-create-home --gecos "" appuser \
    && mkdir -p /app/staticfiles /app/uploads /app/logs \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . /app/

RUN chown -R appuser:appuser /app/staticfiles /app/uploads /app/logs

USER appuser
