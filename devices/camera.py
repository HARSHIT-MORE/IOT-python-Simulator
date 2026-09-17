import random
import time

from devices.base_device import BaseDevice


class Camera(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="camera",

            cpu=0.8,
            ram=0.8,
            battery=0.6,
            bandwidth=0.8,

            location="room",
            normal_time="00:00-23:59"
        )

    def generate_data(self):

        event = random.choice([
            "no_person",
            "person_detected",
            "person_detected",
            "no_person"
        ])

        data = {

            "device_id": self.device_id,

            "device_type": self.device_type,

            "event": event,

            "timestamp":
                time.strftime("%Y-%m-%d %H:%M:%S"),

            "status": "normal"
        }

        return data