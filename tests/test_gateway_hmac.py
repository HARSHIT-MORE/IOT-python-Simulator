import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.gateway import Gateway
from gateway.history_manager import HistoryManager
from iot.mqtt_adapter import MQTTDeviceAdapter
from security.crypto import LightweightCrypto
from security.evidence_collector import EvidenceCollector
from tempfile import TemporaryDirectory


class GatewayHMACTests(unittest.TestCase):
    def setUp(self):
        self.gateway = Gateway(None, None, LightweightCrypto(), None)

    def make_observation(self):
        signed_data = {
            "device_id": "CLOCK_001",
            "device_type": "smart_clock",
            "hour": 12,
            "minute": 0,
            "second": 0,
            "boot_id": "boot-test",
            "sequence_number": 1,
            "device_timestamp_epoch": 1792152000,
        }
        raw_signed_json = json.dumps(signed_data, separators=(",", ":"))
        signature = hmac.new(
            b"clock_secret_key", raw_signed_json.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        raw_payload = raw_signed_json[:-1] + ',"message_signature":"' + signature + '"}'
        parsed = json.loads(raw_payload)
        # The adapter adds these fields after verifying the original payload.
        parsed["device_hmac_valid"] = True
        parsed["integrity_status"] = "VERIFIED"
        return {
            "device_id": "CLOCK_001",
            "device_type": "smart_clock",
            "raw_data": parsed,
            "raw_payload": raw_payload,
        }

    def test_adapter_to_gateway_end_to_end_signature_verification(self):
        observation = self.make_observation()
        adapted = MQTTDeviceAdapter().process_message(
            "harshit/iot/CLOCK_001", observation["raw_payload"]
        )
        result = self.gateway.verify_message_authentication(adapted)
        self.assertTrue(adapted["device_hmac_valid"])
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["integrity_status"], "VERIFIED")

    def test_gateway_accepts_valid_raw_device_signature(self):
        observation = self.make_observation()
        result = self.gateway.verify_message_authentication(observation)
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["integrity_status"], "VERIFIED")

    def test_gateway_denies_invalid_hmac_even_when_trust_is_high(self):
        observation = self.make_observation()
        observation["raw_payload"] = observation["raw_payload"].replace('"hour":12', '"hour":13')
        observation["adaptive_trust"] = {"trust_score": 0.99, "trust_status": "TRUSTED"}
        observation["risk_analysis"] = {"risk_score": 0.01, "risk_status": "LOW"}
        observation["decision_analysis"] = {
            "decision": "ALLOW", "reason": "High trust and low risk",
            "security_action": "ALLOW_REQUEST", "requires_evidence": False,
            "requires_isolation": False,
        }
        observation["resource_analysis"] = {"rcf": 0.75, "resource_pressure": 0.1}
        with TemporaryDirectory() as evidence_dir:
            gateway = Gateway(
                None, EvidenceCollector(evidence_dir), LightweightCrypto(), HistoryManager()
            )
            result = gateway.receive_data(observation)
            self.assertEqual(result["decision"], "DENY")
            self.assertFalse(gateway.is_device_isolated("CLOCK_001"))
            indicators = result["forensic_analysis"]["indicators_of_compromise"]
            self.assertNotIn("Highly abnormal behavior", indicators)
            self.assertNotIn("Highly abnormal context", indicators)
            self.assertFalse(result["forensic_analysis"]["confirmed_attack"])

    def test_gateway_rejects_modified_raw_payload(self):
        observation = self.make_observation()
        observation["raw_payload"] = observation["raw_payload"].replace('"hour":12', '"hour":13')
        result = self.gateway.verify_message_authentication(observation)
        self.assertFalse(result["authenticated"])
        self.assertEqual(result["integrity_status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
