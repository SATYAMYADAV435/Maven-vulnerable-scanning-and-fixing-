FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Default port for FastAPI server
EXPOSE 8000

# Default entrypoint starts the API server; can be overridden for CLI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
