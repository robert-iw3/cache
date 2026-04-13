#!/usr/bin/env python3
"""
test_baseline_learner.py - Unit & Smoke Test for baseline_learner.py (v2.7)
"""

import os
import time
import json
import unittest
from pathlib import Path
import joblib
from baseline_learner import BaselineLearner

class TestBaselineLearner(unittest.TestCase):

    def setUp(self):
        """Clean up before each test"""
        if Path("baseline.db").exists():
            os.remove("baseline.db")
        if Path("baseline_model.joblib").exists():
            os.remove("baseline_model.joblib")
        self.learner = BaselineLearner()

    def tearDown(self):
        """Clean up after each test"""
        self.learner.stop()
        if Path("baseline.db").exists():
            os.remove("baseline.db")
        if Path("baseline_model.joblib").exists():
            os.remove("baseline_model.joblib")

    def test_database_creation(self):
        """Test that database and table are created"""
        self.assertTrue(Path("baseline.db").exists())
        cursor = self.learner.db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='flows'")
        self.assertIsNotNone(cursor.fetchone())

    def test_record_flow(self):
        """Test recording a flow"""
        self.learner.record_flow(
            process_name="firefox",
            dst_ip="142.250.190.78",
            interval=65.3,
            cv=0.12,
            outbound_ratio=0.95,
            entropy=3.8,
            packet_size_mean=1420,
            packet_size_std=340
        )
        cursor = self.learner.db.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)

    def test_learn_creates_model(self):
        """Test that learn() creates a valid model file"""
        # Add some test data
        for i in range(15):
            self.learner.record_flow(
                process_name="firefox",
                dst_ip="142.250.190.78",
                interval=60 + i,
                cv=0.1,
                outbound_ratio=0.9,
                entropy=3.5,
                packet_size_mean=1400,
                packet_size_std=300
            )

        self.learner.learn()
        self.assertTrue(Path("baseline_model.joblib").exists())

    def test_model_structure(self):
        """Test that saved model has correct structure"""
        # Add data and learn
        for i in range(12):
            self.learner.record_flow("python", "8.8.8.8", 45, 0.2, 0.85, 4.1, 800, 150)
        self.learner.learn()

        model = joblib.load("baseline_model.joblib")
        self.assertIn("version", model)
        self.assertIn("profiles", model)
        self.assertGreater(len(model["profiles"]), 0)

    def test_cleanup_old_data(self):
        """Test data retention / cleanup"""
        # Insert old data
        old_time = time.time() - 86400 * 40  # 40 days old
        self.learner.db.execute("INSERT INTO flows (timestamp) VALUES (?)", (old_time,))
        self.learner.db.commit()

        self.learner.cleanup_old_data()

        cursor = self.learner.db.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 0)  # All old data should be cleaned

    def test_stop(self):
        """Test graceful stop"""
        self.learner.stop()
        self.assertFalse(self.learner.running)


if __name__ == "__main__":
    print("Running baseline_learner.py unit & smoke tests...\n")
    unittest.main(verbosity=2)