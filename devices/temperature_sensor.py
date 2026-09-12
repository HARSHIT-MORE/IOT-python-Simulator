import random
import time


class TemperatureSensor:

    def __init__(self, device_id):
        self.device_id = device_id
        self.trust_score = 0.95

    def generate_data(self):

        temperature = round(random.uniform(20, 35), 2)

        data = {
            "device_id": self.device_id,
            "device_type": "temperature_sensor",
            "temperature": temperature,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trust_score": self.trust_score,
            "status": "normal"
        }

        return data