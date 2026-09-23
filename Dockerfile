FROM python:3.11-slim

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY ThreatTraceAI/backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY ThreatTraceAI/backend /app

EXPOSE 8000
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
