"""
Unit tests for Model Registry, Staging, Promotion, and Rollback.
"""

import os
import shutil
import unittest
import tempfile
from models.registry import ModelRegistry, DEFAULT_CHAMPION_PATH

class TestModelRegistry(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.registry = ModelRegistry(models_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_registry_initialization(self):
        status = self.registry.get_status()
        self.assertEqual(status["active_champion"], "v1.0.0-baseline")
        self.assertIsNone(status["active_challenger"])
        self.assertFalse(status["shadow_evaluation_enabled"])

    def test_register_and_stage_candidate(self):
        # Register default model as a candidate in the test registry
        cand_id = self.registry.register_candidate(DEFAULT_CHAMPION_PATH)
        self.assertTrue(cand_id.startswith("v"))
        
        # Stage as Challenger
        self.registry.stage_challenger(cand_id, enable_shadow=True)
        status = self.registry.get_status()
        self.assertEqual(status["active_challenger"], cand_id)
        self.assertTrue(status["shadow_evaluation_enabled"])

    def test_promote_and_rollback_cycle(self):
        cand_id = self.registry.register_candidate(DEFAULT_CHAMPION_PATH)
        self.registry.stage_challenger(cand_id, enable_shadow=True)
        
        # Promote to Champion
        promoted = self.registry.promote_challenger_to_champion()
        self.assertEqual(promoted, cand_id)
        status = self.registry.get_status()
        self.assertEqual(status["active_champion"], cand_id)
        self.assertIsNone(status["active_challenger"])

        # Rollback
        reverted = self.registry.rollback_to_previous()
        self.assertEqual(reverted, "v1.0.0-baseline")
        status_after_rollback = self.registry.get_status()
        self.assertEqual(status_after_rollback["active_champion"], "v1.0.0-baseline")

if __name__ == "__main__":
    unittest.main()
