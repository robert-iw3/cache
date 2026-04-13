# ==============================================================================
# Stage 1: eBPF Builder
# ==============================================================================
FROM docker.io/ubuntu:25.10 AS builder
ARG DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update && \
    apt-get install -y \
        clang \
        gcc \
        llvm \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        make \
        linux-tools-common \
        linux-tools-generic \
        bpftool && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# NOTE: You MUST have generated vmlinux.h locally in ebpf/probes/ before building!
COPY ebpf/probes /build/probes

RUN cd probes && make

# ==============================================================================
# Stage 2: Final Image
# ==============================================================================
FROM docker.io/ubuntu:25.10
ARG DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update && \
    apt-get install -y \
        iproute2 \
        procps \
        curl \
        python3 \
        python3-venv \
        libbpf1 \
        libelf1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

COPY --from=builder /build/probes/c2_probe.bpf.o /app/ebpf/probes/c2_probe.bpf.o
COPY --from=builder /build/probes/c2_loader /app/ebpf/probes/c2_loader

RUN python3 -m venv --system-site-packages /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt