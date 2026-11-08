import hashlib
import hmac
import json
import unittest
from iot.mqtt_adapter import MQTTDeviceAdapter
from security.crypto import LightweightCrypto

class DeviceHMACTests(unittest.TestCase):
    def make_payload(self, device_id="CLOCK_001", extra=None, key=b"clock_secret_key"):
        data = {"device_id": device_id, "device_type": "smart_clock", "hour": 12,
                "minute": 0, "second": 0, "boot_id": "boot-test",
                "sequence_number": 1, "device_timestamp_epoch": 1792152000}
        if extra: data.update(extra)
        # Match firmware's exact compact JSON string; signature is appended last.
        base = json.dumps(data, separators=(",", ":"))
        signature = hmac.new(key, base.encode(), hashlib.sha256).hexdigest()
        return base[:-1] + ',"message_signature":"' + signature + '"}', data

    def test_valid_device_signature(self):
        payload, _ = self.make_payload()
        adapter = MQTTDeviceAdapter()
        obs = adapter.process_message("harshit/iot/CLOCK_001", payload)
        self.assertIsNotNone(obs)
        self.assertTrue(obs["device_hmac_valid"])
        self.assertEqual(obs["integrity_status"], "VERIFIED")
        crypto = LightweightCrypto()
        self.assertTrue(crypto.verify_hmac_raw_payload("CLOCK_001", payload, obs["raw_data"]["message_signature"]))

    def test_modified_payload_fails_signature(self):
        payload, _ = self.make_payload()
        payload = payload.replace('"hour":12', '"hour":13')
        obs = MQTTDeviceAdapter().process_message("harshit/iot/CLOCK_001", payload)
        self.assertIsNotNone(obs)
        self.assertFalse(obs["device_hmac_valid"])
        self.assertEqual(obs["integrity_status"], "FAILED")

    def test_adapter_preserves_exact_raw_payload(self):
        payload, _ = self.make_payload()
        observation = MQTTDeviceAdapter().process_message("harshit/iot/CLOCK_001", payload)
        self.assertEqual(observation["raw_payload"], payload)
        self.assertTrue(observation["device_hmac_valid"])
        # Adapter metadata is added to the parsed dict, not to the signed raw text.
        self.assertIn('"message_signature":', observation["raw_payload"])
        self.assertNotIn('"integrity_status":', observation["raw_payload"])

    def test_invalid_signature_cannot_poison_sequence_state(self):
        adapter = MQTTDeviceAdapter()
        payload1, _ = self.make_payload(extra={"sequence_number": 1})
        first = adapter.process_message("harshit/iot/CLOCK_001", payload1)
        self.assertTrue(first["device_hmac_valid"])

        # Inject a much higher sequence with a broken signature.
        hostile_payload, _ = self.make_payload(extra={"sequence_number": 999})
        hostile_payload = hostile_payload.replace('"hour":12', '"hour":13')
        hostile = adapter.process_message("harshit/iot/CLOCK_001", hostile_payload)
        self.assertIsNotNone(hostile)
        self.assertFalse(hostile["device_hmac_valid"])
        self.assertEqual(adapter.last_sequence_state["CLOCK_001"]["sequence_number"], 1)

        # The next valid sequence remains acceptable.
        payload2, _ = self.make_payload(extra={"sequence_number": 2})
        second = adapter.process_message("harshit/iot/CLOCK_001", payload2)
        self.assertIsNotNone(second)
        self.assertTrue(second["device_hmac_valid"])
        self.assertEqual(adapter.last_sequence_state["CLOCK_001"]["sequence_number"], 2)

    def test_missing_signature_is_unverified_not_tampering(self):
        data = {"device_id": "CLOCK_001", "device_type": "smart_clock", "hour": 12,
                "minute": 0, "second": 0, "boot_id": "boot-test", "sequence_number": 1,
                "device_timestamp_epoch": 1792152000}
        payload = json.dumps(data, separators=(",", ":"))
        obs = MQTTDeviceAdapter().process_message("harshit/iot/CLOCK_001", payload)
        self.assertIsNotNone(obs)
        self.assertIsNone(obs["device_hmac_valid"])
        self.assertEqual(obs["integrity_status"], "UNVERIFIED")

if __name__ == "__main__": unittest.main()
