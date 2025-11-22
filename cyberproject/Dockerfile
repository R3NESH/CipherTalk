# Use official Python runtime
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# 1. Install system dependencies required for CatBoost (libgomp1 is mandatory)
RUN apt-get update && apt-get install -y \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# 2. Copy requirements and install dependencies
COPY server/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 3. Copy the application folders
COPY server /app/server
COPY mlmodel /app/mlmodel
COPY client /app/client

# 4. Set Python path so 'server' modules can talk to each other
ENV PYTHONPATH=/app/server

# 5. (Optional) Run your test script during build to catch errors early
# If this fails, the deployment will stop (saving you debugging time)
RUN python /app/server/test_startup.py

# Expose the port
EXPOSE 8000

# 6. Start the application
# Note: We point to "server.main:app" because main.py is inside the server folder
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
