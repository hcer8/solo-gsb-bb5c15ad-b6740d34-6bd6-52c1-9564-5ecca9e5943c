FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# SQLite policy database lives here; a Docker volume is mounted at this path.
# Owned by the unprivileged runtime user so it can create/rename files in it.
RUN mkdir -p /data && chown nobody:nogroup /data
VOLUME ["/data"]
ENV POLICY_DB=/data/policies.db

EXPOSE 8080

USER nobody

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
