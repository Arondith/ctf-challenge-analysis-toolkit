FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CTF_WORKSPACE=/workspace
ENV CTF_CONFIG=/app/config/config.yaml

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       file \
       binutils \
       unzip \
       xxd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --no-cache-dir \
    -r /app/backend/requirements.txt

COPY . /app

RUN mkdir -p /workspace/artifacts

EXPOSE 8000

CMD [
    "uvicorn",
    "backend.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000"
]
