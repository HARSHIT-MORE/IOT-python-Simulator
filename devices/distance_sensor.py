"""HC-SR04 distance sensor model used by the MQTT simulator."""
import math
import time

from devices.base_device import BaseDevice


class DistanceSensor(BaseDevice):
    MIN_DISTANCE_CM = 2.0
    MAX_DISTANCE_CM = 400.0

    def __init__(self, device_id):
        super().__init__(
            device_id=device_id,
            device_type="ultrasonic_distance_sensor",
            cpu=0.3,
            ram=0.3,
            battery=0.8,
            bandwidth=0.3,
            location="room",
            normal_time="00:00-23:59",
        )

    def update_from_mqtt(self, mqtt_data):
        distance = mqtt_data.get("distance_cm")
        if isinstance(distance, bool) or not isinstance(distance, (int, float)) or not math.isfinite(float(distance)):
            raise ValueError("MQTT data must contain a finite numeric distance_cm")
        if not self.MIN_DISTANCE_CM <= float(distance) <= self.MAX_DISTANCE_CM:
            raise ValueError("distance_cm must be between 2 and 400 centimeters")
        data = {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "distance_cm": float(distance),
            "timestamp": mqtt_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": mqtt_data.get("status", "normal"),
            "source": "ESP32_HC_SR04",
        }
        self.latest_mqtt_data = data
        return data

    def generate_data(self):
        if self.latest_mqtt_data is not None:
            return self.latest_mqtt_data.copy()
        return {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "waiting_for_mqtt",
            "source": "NO_MQTT_DATA",
        }
