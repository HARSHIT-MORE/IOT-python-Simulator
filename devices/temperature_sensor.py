import random
import time

from devices.base_device import BaseDevice


class TemperatureSensor(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="temperature_sensor",

            # Resource capability
            cpu=0.2,
            ram=0.2,
            battery=0.9,
            bandwidth=0.2,

            # Context
            location="room",
            normal_time="00:00-23:59"
        )

    def generate_data(self):

        temperature = round(
            random.uniform(20, 35),
            2
        )

        data = {

            "device_id": self.device_id,

            "device_type": self.device_type,

            "temperature": temperature,

            "timestamp":
                time.strftime("%Y-%m-%d %H:%M:%S"),

            "status": "normal"
        }

        return data