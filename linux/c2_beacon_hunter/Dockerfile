FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y \
    iproute2 \
    procps \
    auditd \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN python -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Output directory
RUN mkdir -p /app/output

# Must run as root for privileged host access
USER root

CMD ["/app/venv/bin/python", "c2_beacon_hunter.py"]