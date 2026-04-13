FROM docker.io/ubuntu:25.10 AS builder

RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev libbpf-dev bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY ebpf/ /build/ebpf/
RUN cd /build/ebpf && make

FROM docker.io/ubuntu:25.10

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    iproute2 net-tools curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY v3.0/agent/agent_runner.py /app/
COPY v3.0/agent/config.ini.example /app/config.ini
COPY v3.0/agent/libbpf_collector.py /app/
COPY probes/ /app/probes/

COPY --from=builder /build/ebpf/ /app/ebpf/

RUN python3 -m venv /venv && \
    /venv/bin/pip install requests psutil numpy

ENV PATH="/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

RUN useradd -m appuser
USER appuser

HEALTHCHECK --interval=30s --timeout=3s CMD python3 -c "import requests; requests.get('http://localhost/health', timeout=1)" || exit 1

CMD ["python3", "/app/agent_runner.py"]