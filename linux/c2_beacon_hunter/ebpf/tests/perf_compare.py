#!/usr/bin/env python3
"""
perf_compare.py - Performance comparison for BCC vs libbpf backends
"""

import time
import psutil
import os
import subprocess
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_backend(backend):
    logger.info(f"Testing {backend} backend...")
    process = subprocess.Popen([sys.executable, "src/collector_factory.py", "--backend", backend],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = process.pid
    p = psutil.Process(pid)

    time.sleep(10)  # Run for 10 seconds

    cpu = p.cpu_percent(interval=1)
    memory = p.memory_info().rss / 1024 / 1024  # MB
    process.terminate()

    return cpu, memory

def main():
    logger.info("Running performance comparison...")
    cpu_bcc, mem_bcc = run_backend("bcc")
    cpu_libbpf, mem_libbpf = run_backend("libbpf")

    logger.info(f"BCC: CPU {cpu_bcc}% | Memory {mem_libbpf} MB")
    logger.info(f"libbpf: CPU {cpu_libbpf}% | Memory {mem_libbpf} MB")

if __name__ == "__main__":
    main()