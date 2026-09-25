FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

# Build context is the repository root: the backend imports the shared packet/flow code in capture/
COPY backend/ .
COPY capture/ ./capture/
COPY worldmodel_v2/ ./worldmodel_v2/
COPY worldmodel_v3/ ./worldmodel_v3/

EXPOSE 8000

HEALTHCHECK --interval=5s --timeout=5s --start-period=15s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
