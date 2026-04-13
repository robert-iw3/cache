# syntax=docker/dockerfile:1
ARG repo="docker.io"

FROM ${repo}/rust:1.73 as builder
WORKDIR /usr/src/linux-sentinel
COPY . .
RUN cargo build --release

FROM ${repo}/ubuntu:22.04
LABEL maintainer="Linux Sentinel Team <riweber3@protonmail.com>"
LABEL version="2.3"
LABEL description="Rust-based Linux Sentinel Security Monitoring Tool"

RUN \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libbpf-dev \
        libyara-dev \
        curl \
        netcat-openbsd \
        inotify-tools \
        procps \
        psmisc \
        net-tools \
        lsof \
        iproute2; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/linux-sentinel/target/release/linux-sentinel /opt/linux-sentinel/linux-sentinel
COPY sentinel.conf /opt/linux-sentinel/sentinel.conf
COPY rules.yara /opt/linux-sentinel/rules.yara

WORKDIR /opt/linux-sentinel

RUN \
    mkdir -p /var/log/linux-sentinel /var/backups/linux-sentinel; \
    chown -R nobody:nogroup /var/log/linux-sentinel /var/backups/linux-sentinel; \
    chmod -R 750 /var/log/linux-sentinel /var/backups/linux-sentinel; \
    chmod 755 /opt/linux-sentinel/linux-sentinel

USER nobody
RUN setcap cap_net_admin,cap_dac_read_search,cap_sys_ptrace+ep /opt/linux-sentinel/linux-sentinel

ENV DASHBOARD_PORT=8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${DASHBOARD_PORT}/api/status || exit 1

ENTRYPOINT ["/opt/linux-sentinel/linux-sentinel"]
CMD ["enhanced"]

EXPOSE 8080