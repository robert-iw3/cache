#!/usr/bin/env python3
"""
test_libbpf_collector.py - Unit test for libbpf collector
"""

import unittest
from pathlib import Path
from collector_factory import CollectorFactory

class TestLibBPFCollector(unittest.TestCase):

    def test_factory_can_select_libbpf(self):
        collector = CollectorFactory.create_collector()
        self.assertIsNotNone(collector)
        self.assertTrue(hasattr(collector, 'run'))
        self.assertTrue(hasattr(collector, 'stop'))

    def test_probe_file_exists(self):
        probe_path = Path("../probes/c2_probe.bpf.o")
        self.assertTrue(probe_path.exists(), "c2_probe.bpf.o must exist for libbpf backend")


if __name__ == "__main__":
    unittest.main(verbosity=2)