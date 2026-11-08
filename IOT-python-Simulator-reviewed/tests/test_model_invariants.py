import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.adaptive_weight_engine import AdaptiveWeightEngine
from gateway.resource_manager import ResourceManager
from gateway.trust_engine import TrustEngine


class ModelInvariantTests(unittest.TestCase):
    def test_base_trust_weights_sum_to_one(self):
        weights = AdaptiveWeightEngine().base_weights
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=9)

    def test_behavior_anomaly_increases_behavior_importance(self):
        engine = AdaptiveWeightEngine()
        normal = engine.calculate_adaptive_weights(1.0, 1.0, 1.0, 0.0)
        anomalous = engine.calculate_adaptive_weights(0.4, 1.0, 1.0, 0.0)
        self.assertGreater(anomalous["behavior"], normal["behavior"])
        self.assertAlmostEqual(sum(anomalous.values()), 1.0, delta=0.003)

    def test_trust_equation_uses_one_minus_risk(self):
        result = TrustEngine().calculate_trust(
            behavior_score=0.8,
            context_score=0.9,
            history_score=0.7,
            risk_score=0.2,
            adaptive_weights={
                "behavior_weight": 0.25,
                "context_weight": 0.20,
                "history_weight": 0.30,
                "risk_weight": 0.25,
            },
        )
        self.assertEqual(result, round(0.25 * 0.8 + 0.20 * 0.9 + 0.30 * 0.7 + 0.25 * 0.8, 3))

    def test_rcf_and_resource_pressure_are_separate_metrics(self):
        device = SimpleNamespace(
            cpu=0.8, ram=0.6, battery=0.9, bandwidth=0.7,
            cpu_usage=0.4, ram_usage=0.5, battery_level=0.6,
            bandwidth_usage=0.3,
        )
        manager = ResourceManager()
        self.assertEqual(manager.calculate_rcf(device), 0.75)
        self.assertEqual(manager.calculate_resource_pressure(device), 0.41)


if __name__ == "__main__":
    unittest.main()
