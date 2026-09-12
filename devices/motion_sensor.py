import random
import time


class MotionSensor:

    def __init__(self, device_id):
        self.device_id = device_id
        self.trust_score = 0.95

    def generate_data(self):

        motion = random.choice([
            "detected",
            "not_detected"
        ])

        data = {
            "device_id": self.device_id,
            "device_type": "motion_sensor",
            "motion": motion,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trust_score": self.trust_score,
            "status": "normal"
        }

        return data