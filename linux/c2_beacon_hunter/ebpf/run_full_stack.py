#!/usr/bin/env python3
"""
run_full_stack.py - v2.8 Unified Launcher
Starts: c2_beacon_hunter + baseline_learner + eBPF collector
"""

import subprocess
import time
import sys
import os
import logging
from pathlib import Path
import argparse

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main(args):
    logger.info("="*80)
    logger.info(" c2_beacon_hunter v2.8 - Full Stack Launcher")
    logger.info("="*80)
    logger.info("Starting: Hunter + Baseline Learner + eBPF Collector")
    logger.info("")

    processes = []

    try:
        # Determine path to main hunter (works in Docker or local)
        hunter_path = Path("../c2_beacon_hunter.py") if Path("../c2_beacon_hunter.py").exists() else Path("c2_beacon_hunter.py")

        # 1. Start Baseline Learner
        logger.info("[1/3] Starting Baseline Learner...")
        learner = subprocess.Popen([sys.executable, "src/baseline_learner.py"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(learner)

        # 2. Start eBPF Collector
        logger.info("[2/3] Starting eBPF Collector...")
        collector = subprocess.Popen([sys.executable, "src/collector_factory.py"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(collector)

        # 3. Start Main Hunter
        logger.info("[3/3] Starting Main Hunter...")
        hunter = subprocess.Popen([sys.executable, str(hunter_path)])
        processes.append(hunter)

        logger.info("\nAll components started successfully!")
        logger.info("Press Ctrl+C to stop everything gracefully.\n")

        # Keep main thread alive
        hunter.wait()

    except KeyboardInterrupt:
        logger.info("\n\nShutting down all components...")
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        logger.info("All components stopped.")

    except Exception as e:
        logger.error(f"Launcher error: {e}")
        for p in processes:
            if p.poll() is None:
                p.kill()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="v2.8 Launcher")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        logger.warning("Warning: eBPF collector requires root privileges.")
        logger.warning("Run with: sudo python3 run_full_stack.py")
        sys.exit(1)

    main(args)