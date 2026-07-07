# ═══════════════════════════════════════════════════════════════
# VulnApp — Supply Chain Security Demo Container
# ═══════════════════════════════════════════════════════════════
# Uses Python 3.9-slim with intentionally outdated dependencies
# for supply chain security monitoring demonstration.
#
# WARNING: This image contains known vulnerable packages.
#          Do NOT deploy in production environments.
# ═══════════════════════════════════════════════════════════════

FROM python:3.9-slim

LABEL maintainer="Supply Chain Sentinel Project"
LABEL description="Intentionally vulnerable demo application for security research"
LABEL version="1.0.0"
LABEL phase="1"

# ─── Environment Variables ───────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ─── System Dependencies ────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxslt1-dev \
        libffi-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ─── Python Dependencies ────────────────────────────────────
# Install in a separate layer for better caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# ─── Application Code ───────────────────────────────────────
COPY main.py .

# ─── Container Configuration ────────────────────────────────
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ─── Entrypoint ─────────────────────────────────────────────
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
