#!/usr/bin/env python3
"""
test_ebpf_collector.py - Unit & Smoke Test for eBPF Collector
"""

import unittest
import time
import os
from pathlib import Path
from ebpf_collector import EBPFCollector

class TestEBPFCollector(unittest.TestCase):

    def setUp(self):
        self.collector = EBPFCollector()

    def tearDown(self):
        if self.collector.running:
            self.collector.stop()

    def test_probes_load_without_error(self):
        """Test that eBPF probes load successfully"""
        try:
            self.collector.load_probes()
            self.assertIsNotNone(self.collector.bpf)
            print("Probes loaded successfully")
        except Exception as e:
            self.fail(f"Probe loading failed: {e}")

    def test_callback_to_learner(self):
        """Test that events are passed to baseline_learner"""
        # This is a smoke test - real eBPF events require root + kernel
        print("Smoke test: callback system ready (full test requires root + eBPF)")
        self.assertTrue(hasattr(self.collector, 'process_event'))

    def test_stop_graceful(self):
        """Test graceful shutdown"""
        self.collector.stop()
        self.assertFalse(self.collector.running)


if __name__ == "__main__":
    print("Running eBPF Collector tests...\n")
    unittest.main(verbosity=2)