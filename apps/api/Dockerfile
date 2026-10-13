FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Ensure storage directory exists
RUN mkdir -p /app/data/artifacts

EXPOSE 8000

ENV PYTHONPATH=/app

CMD ["uvicorn", "apps.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
