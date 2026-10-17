import csv
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.attack_visualizer import ExperimentVisualizer
from security.device_attack_detector import DeviceAttackDetector


class LiveTemperatureAndMetricsTests(unittest.TestCase):
    def observation(self, temperature, received_at):
        raw = {"temperature": temperature, "humidity": 45.0}
        return {
            "device_id": "TEMP_001", "device_type": "temperature_sensor",
            "temperature": temperature, "humidity": 45.0, "raw_data": raw,
            "_received_at_epoch": received_at, "source": "ESP32_MQTT",
            "timestamp": str(received_at), "integrity_status": "VERIFIED",
            "device_hmac_valid": True,
        }

    def test_first_temperature_is_baseline(self):
        detector = DeviceAttackDetector()
        result = detector.analyze(self.observation(24.0, 100.0))
        self.assertFalse(result["anomaly_detected"])
        self.assertEqual(result["indicators"], [])

    def test_rate_limit_uses_elapsed_time_and_per_type_configuration(self):
        detector = DeviceAttackDetector()
        detector.TEMPERATURE_LIMITS = {
            "temperature_sensor": {"max_change_c": 5.0, "max_change_c_per_second": 0.5}
        }
        detector.analyze(self.observation(24.0, 100.0))
        fast = detector.analyze(self.observation(26.0, 101.0))
        self.assertTrue(fast["anomaly_detected"])
        self.assertEqual(fast["indicators"][0]["attack_type"], "TEMPERATURE_RATE_ANOMALY")

        detector = DeviceAttackDetector()
        detector.TEMPERATURE_LIMITS = {
            "temperature_sensor": {"max_change_c": 5.0, "max_change_c_per_second": 0.5}
        }
        detector.analyze(self.observation(24.0, 100.0))
        gradual = detector.analyze(self.observation(26.0, 110.0))
        self.assertFalse(gradual["anomaly_detected"])

    def test_round_csv_matches_recorded_scores_and_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            visualizer = ExperimentVisualizer(directory)
            device = SimpleNamespace(device_id="TEMP_001", device_type="temperature_sensor")
            data = self.observation(31.5, 120.0)
            data["device_attack_indicators"] = [{"attack_type": "TEMPERATURE_RATE_ANOMALY"}]
            visualizer.record(
                round_number=2, device=device, data=data, behavior_score=0.7,
                context_score=0.8, history_score=0.9, risk_score=0.3,
                trust_score=0.72, rcf=0.6, resource_pressure=0.2,
                adaptive_weights={"behavior": 0.4, "context": 0.2, "history": 0.2, "risk": 0.2},
                decision_result={"decision": "MONITOR", "security_action": "ALLOW_WITH_MONITORING"},
                scenario_label="LIVE_UNLABELLED",
            )
            paths = visualizer.save_and_plot()
            with open(paths["csv"], newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["temperature"], "31.5")
            self.assertEqual(row["trust_score"], "0.72")
            self.assertEqual(row["risk_score"], "0.3")
            self.assertIn("TEMPERATURE_RATE_ANOMALY", row["detection_result"])
            self.assertEqual(row["integrity_status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
