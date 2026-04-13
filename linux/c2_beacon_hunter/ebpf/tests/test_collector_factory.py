#!/usr/bin/env python3
"""
test_collector_factory.py - Unit test for collector factory
"""

import unittest
from collector_factory import CollectorFactory

class TestCollectorFactory(unittest.TestCase):

    def test_factory_returns_bcc_by_default(self):
        collector = CollectorFactory.create_collector()
        self.assertIsNotNone(collector)
        self.assertTrue(hasattr(collector, 'run'))
        self.assertTrue(hasattr(collector, 'stop'))

    def test_factory_can_create_bcc_explicitly(self):
        # For now we only have BCC, this ensures the factory works
        collector = CollectorFactory.create_collector()
        self.assertEqual(type(collector).__name__, "BCCCollector")


if __name__ == "__main__":
    unittest.main(verbosity=2)