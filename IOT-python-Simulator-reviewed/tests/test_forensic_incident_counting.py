import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.history_manager import HistoryManager


class ForensicIncidentCountingTests(unittest.TestCase):
    def test_suspected_tampering_is_not_counted_as_confirmed_attack(self):
        history = HistoryManager()
        result = history.record_forensic_incident("CLOCK_001", {
            "attack_type": "MESSAGE_TAMPERING_SUSPECTED",
            "severity": "LOW",
            "severity_score": 0.2,
            "indicators_of_compromise": ["Message integrity verification failed"],
            "confirmed_attack": False,
        })
        self.assertEqual(result["forensic_incidents"], 1)
        self.assertEqual(result["confirmed_incidents"], 0)

    def test_explicitly_confirmed_attack_is_counted(self):
        history = HistoryManager()
        result = history.record_forensic_incident("MOTION_001", {
            "attack_type": "UNAUTHORIZED_COMMAND",
            "severity": "LOW",
            "severity_score": 0.2,
            "indicators_of_compromise": ["Unauthorized command"],
            "confirmed_attack": True,
        })
        self.assertEqual(result["forensic_incidents"], 1)
        self.assertEqual(result["confirmed_incidents"], 1)


if __name__ == "__main__":
    unittest.main()
