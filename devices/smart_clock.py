import time
import random


class SmartClock:

    def __init__(self, device_id):
        self.device_id = device_id
        self.trust_score = 0.95

    def generate_data(self):

        current_time = time.strftime("%H:%M:%S")

        # Normal clock data
        temperature = round(random.uniform(22, 30), 2)

        data = {
            "device_id": self.device_id,
            "device_type": "smart_clock",
            "time": current_time,
            "temperature": temperature,
            "trust_score": self.trust_score,
            "status": "normal"
        }

        return data