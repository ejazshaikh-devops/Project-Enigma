# GuardAI Backend — Production Dockerfile
# Multi-stage build: smaller final image, no build tools in production layer.

# ── Stage 1: Build dependencies ────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.12-slim

# Create non-root user — never run the app as root
RUN groupadd -r guardai && useradd -r -g guardai -d /app -s /sbin/nologin guardai

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /root/.local /home/guardai/.local

COPY . .

# Ensure non-root user owns the app directory
RUN chown -R guardai:guardai /app

USER guardai
ENV PATH=/home/guardai/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://localhost:8000/v1/health/live', timeout=3).status==200 else sys.exit(1)"

# GUNICORN_WORKERS is read at container start, not build time, so you can
# tune it per-instance-size without rebuilding the image:
#   t3.micro  (1GB RAM) -> GUNICORN_WORKERS=1
#   t3.small  (2GB RAM) -> GUNICORN_WORKERS=2  (default)
#   t3.medium (4GB RAM) -> GUNICORN_WORKERS=3-4
# Rule of thumb: 1 worker per ~512MB-1GB of available RAM for this app.
ENV GUNICORN_WORKERS=2

# Shell form so $GUNICORN_WORKERS expands from the container's environment
CMD gunicorn main:app \
    --workers ${GUNICORN_WORKERS} \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --timeout 30 \
    --graceful-timeout 15 \
    --max-requests 2000 \
    --max-requests-jitter 200 \
    --access-logfile - \
    --error-logfile -
