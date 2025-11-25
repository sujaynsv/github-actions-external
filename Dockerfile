# Use a slim, maintained base image
FROM python:3.11-slim

# Install security-related system packages if needed (keep minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m appuser
WORKDIR /app

# Copy and install Python deps
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY app/ /app/

# Drop privileges
USER appuser

# Expose port and entrypoint
EXPOSE 8000
CMD ["python", "main.py"]
