# backend/myproject/Dockerfile
# 1. Python Official Base Image
FROM python:3.13-slim

# 2. Environment Variables set (Python Output & Bytecode optimize)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 3. System package install (PostgreSQL, build tools, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 4. App directory setup
WORKDIR /app

# 5. Dependencies install
COPY requirements.txt /app/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 6. All project file copy
COPY . /app/

# 7. Static & Media directory setup
RUN mkdir -p /app/staticfiles /app/uploads /app/logs
RUN adduser --disabled-password --no-create-home appuser \
    && chown -R appuser:appuser /app/staticfiles /app/uploads /app/logs
USER appuser

# 8. Expose port (Django default: 8000)
EXPOSE 8000

# 9. server run command (Gunicorn)
CMD ["gunicorn", "backend.wsgi:application", "--bind", "0.0.0.0:8000"]
