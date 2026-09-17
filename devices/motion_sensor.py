import random
import time

from devices.base_device import BaseDevice


class MotionSensor(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="motion_sensor",

            cpu=0.3,
            ram=0.3,
            battery=0.8,
            bandwidth=0.3,

            location="room",
            normal_time="00:00-23:59"
        )

    def generate_data(self):

        motion = random.choice(
            ["detected", "not_detected"]
        )

        data = {

            "device_id": self.device_id,

            "device_type": self.device_type,

            "motion": motion,

            "timestamp":
                time.strftime("%Y-%m-%d %H:%M:%S"),

            "status": "normal"
        }

        return data