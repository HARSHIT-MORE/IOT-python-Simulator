import random
import time

from devices.base_device import BaseDevice


class SmartClock(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="smart_clock",

            cpu=0.5,
            ram=0.5,
            battery=0.7,
            bandwidth=0.5,

            location="room",
            normal_time="00:00-23:59"
        )

    def generate_data(self):

        current_time = time.strftime("%H:%M:%S")

        temperature = round(
            random.uniform(22, 30),
            2
        )

        data = {

            "device_id": self.device_id,

            "device_type": self.device_type,

            "time": current_time,

            "temperature": temperature,

            "status": "normal"
        }

        return data