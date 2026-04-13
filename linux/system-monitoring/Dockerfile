# syntax=docker/dockerfile:1
ARG repo="docker.io"

FROM ${repo}/ubuntu:22.04

LABEL maintainer="Linux Sentinel Team <riweber3@protonmail.com>"
LABEL version="2.3"
LABEL description="Linux Sentinel Security Monitoring Tool"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    bpfcc-tools \
    libbpfcc \
    yara \
    netcat-openbsd \
    curl \
    jq \
    inotify-tools \
    procps \
    psmisc \
    net-tools \
    lsof \
    iproute2 \
    systemd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    bcc==0.24.0

COPY linux_sentinel.py /opt/linux-sentinel/linux_sentinel.py
COPY sentinel.conf /opt/linux-sentinel/sentinel.conf

WORKDIR /opt/linux-sentinel

RUN mkdir -p /var/log/linux-sentinel /var/backups/linux-sentinel \
    && chown -R nobody:nogroup /var/log/linux-sentinel /var/backups/linux-sentinel \
    && chmod -R 750 /var/log/linux-sentinel /var/backups/linux-sentinel \
    && chmod 755 /opt/linux-sentinel/linux_sentinel.py

USER nobody
RUN setcap cap_net_admin,cap_dac_read_search,cap_sys_ptrace+ep /opt/linux-sentinel/linux_sentinel.py

ENV PYTHONUNBUFFERED=1 \
    DASHBOARD_PORT=8080 \
    PATH=/opt/linux-sentinel:$PATH

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${DASHBOARD_PORT}/api/status || exit 1

ENTRYPOINT ["python3", "/opt/linux-sentinel/linux_sentinel.py"]
CMD ["enhanced"]

EXPOSE 8080