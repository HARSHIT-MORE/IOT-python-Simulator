import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iot.mqtt_adapter import MQTTDeviceAdapter
from security.device_attack_detector import DeviceAttackDetector


class UltrasonicDistanceTests(unittest.TestCase):
    def test_adapter_normalizes_distance_payload(self):
        payload = json.dumps({
            "device_id": "DISTANCE_001",
            "device_type": "ultrasonic_distance_sensor",
            "distance_cm": 84.5,
            "status": "normal",
        })
        observation = MQTTDeviceAdapter().process_message(
            "harshit/iot/DISTANCE_001", payload
        )
        self.assertEqual(observation["device_type"], "ultrasonic_distance_sensor")
        self.assertEqual(observation["distance_cm"], 84.5)

    def test_first_distance_is_baseline_and_large_jump_is_suspicious(self):
        detector = DeviceAttackDetector()
        baseline = {
            "device_id": "DISTANCE_001",
            "device_type": "ultrasonic_distance_sensor",
            "distance_cm": 100.0,
            "raw_data": {"distance_cm": 100.0, "device_hmac_valid": True},
            "_received_at_monotonic": 10.0,
        }
        self.assertFalse(detector.analyze(baseline)["anomaly_detected"])

        changed = dict(baseline)
        changed["distance_cm"] = 200.0
        changed["raw_data"] = {"distance_cm": 200.0, "device_hmac_valid": True}
        changed["_received_at_monotonic"] = 11.0
        result = detector.analyze(changed)
        self.assertTrue(result["anomaly_detected"])
        self.assertFalse(result["confirmed_attack"])
        self.assertEqual(result["indicators"][0]["attack_type"], "DISTANCE_CHANGE_ANOMALY")

    def test_distance_outside_hcsr04_range_is_flagged(self):
        detector = DeviceAttackDetector()
        reading = {
            "device_id": "DISTANCE_001",
            "device_type": "ultrasonic_distance_sensor",
            "distance_cm": 401.0,
            "raw_data": {"distance_cm": 401.0},
        }
        result = detector.analyze(reading)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(result["indicators"][0]["attack_type"], "DISTANCE_RANGE_ANOMALY")


if __name__ == "__main__":
    unittest.main()
