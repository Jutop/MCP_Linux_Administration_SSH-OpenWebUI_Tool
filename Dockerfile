FROM python:3.11-slim

# Install SSH client and other utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml /app/
COPY src/ /app/src/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Config file will be mounted as a volume

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose HTTP API port
EXPOSE 3000

# Run the HTTP wrapper (easier for OpenWebUI to connect)
CMD ["python", "-m", "flask", "--app", "ssh_control_mcp.http_wrapper:app", "run", "--host", "0.0.0.0", "--port", "3000"]
