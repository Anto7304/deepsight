FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 ASIVM_DATA_DIR=/data
WORKDIR /srv
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 asivm && mkdir /data && chown asivm /data
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY eval ./eval
COPY scripts ./scripts
COPY lab ./lab
USER asivm
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 CMD curl -fs http://localhost:8000/api/health || exit 1
# single worker on purpose: the processing pipeline serialises identity resolution with an in-process lock
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
