import random
import time


class Camera:

    def __init__(self, device_id):
        self.device_id = device_id
        self.trust_score = 0.95

    def generate_data(self):

        event = random.choice([
            "no_person",
            "person_detected",
            "person_detected",
            "no_person"
        ])

        data = {
            "device_id": self.device_id,
            "device_type": "camera",
            "event": event,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trust_score": self.trust_score,
            "status": "normal"
        }

        return data