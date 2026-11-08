import sys, time, unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security.device_attack_detector import DeviceAttackDetector

def obs(raw):
    return {"device_id": "CLOCK_001", "device_type": "smart_clock", "raw_data": raw}

class ClockTimestampTests(unittest.TestCase):
    def test_signed_epoch_close_to_gateway_is_not_drift(self):
        now = time.time()
        tz = timezone(timedelta(seconds=19800))
        local = datetime.fromtimestamp(now, timezone.utc).astimezone(tz)
        result = DeviceAttackDetector().analyze(obs({"hour": local.hour, "minute": local.minute, "second": local.second, "device_timestamp_epoch": now}))
        self.assertFalse(any(i["attack_type"] == "CLOCK_DRIFT" for i in result["indicators"]))

    def test_hmac_failure_is_not_proof_of_attack_intent(self):
        result = DeviceAttackDetector().analyze(obs({
            "hour": 12, "minute": 0, "second": 0,
            "device_hmac_valid": False,
        }))
        indicator = next(i for i in result["indicators"] if i["attack_type"] == "DEVICE_HMAC_FAILURE")
        self.assertFalse(indicator["confirmed"])
        self.assertFalse(result["confirmed_attack"])

    def test_unsigned_time_of_day_without_epoch_is_not_called_clock_drift(self):
        # Old/unsigned clock messages lack authenticated epoch and timezone data.
        # Their time-of-day mismatch must not be presented as clock drift.
        result = DeviceAttackDetector().analyze(obs({
            "hour": 18, "minute": 17, "second": 41,
            "device_hmac_valid": None,
        }))
        self.assertFalse(any(i["attack_type"] == "CLOCK_DRIFT" for i in result["indicators"]))
        self.assertFalse(result["confirmed_attack"])

    def test_epoch_drift_is_anomaly_not_confirmed_attack(self):
        now = time.time()
        tz = timezone(timedelta(seconds=19800))
        local = datetime.fromtimestamp(now, timezone.utc).astimezone(tz)
        result = DeviceAttackDetector().analyze(obs({"hour": local.hour, "minute": local.minute, "second": local.second, "device_timestamp_epoch": now - 300}))
        indicator = next(i for i in result["indicators"] if i["attack_type"] == "CLOCK_DRIFT")
        self.assertFalse(indicator["confirmed"])
        self.assertGreaterEqual(indicator["observed"], 299)
        self.assertIn("epoch difference", indicator["threshold"])

if __name__ == "__main__": unittest.main()
