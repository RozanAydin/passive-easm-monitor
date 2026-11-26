FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Create non-root user for secure container execution
RUN groupadd --gid 1000 monitor && \
    useradd --uid 1000 --gid monitor --shell /bin/bash --create-home monitor

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY config/ ./config/
COPY src/ ./src/
COPY templates/ ./templates/

RUN mkdir -p /app/data /app/logs /app/reports && \
    chown -R monitor:monitor /app

USER monitor

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--config", "config/config.yaml"]
