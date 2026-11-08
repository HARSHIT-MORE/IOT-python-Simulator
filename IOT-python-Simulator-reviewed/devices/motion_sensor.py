import time

from devices.base_device import BaseDevice


class MotionSensor(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="motion_sensor",

            # ==================================================
            # RESOURCE CAPABILITY
            # ==================================================

            cpu=0.3,
            ram=0.3,
            battery=0.8,
            bandwidth=0.3,

            # ==================================================
            # CONTEXT
            # ==================================================

            location="room",
            normal_time="00:00-23:59"
        )


    # ========================================================
    # MQTT DATA
    # ========================================================

    def update_from_mqtt(self, mqtt_data):

        if "motion_detected" not in mqtt_data:

            raise ValueError(
                "MQTT data does not contain motion_detected"
            )


        motion_detected = bool(
            mqtt_data[
                "motion_detected"
            ]
        )


        timestamp = mqtt_data.get(
            "timestamp"
        )

        if timestamp is None:

            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )


        # ----------------------------------------------------
        # Convert boolean into readable state
        # ----------------------------------------------------

        if motion_detected:

            motion = "detected"

        else:

            motion = "not_detected"


        data = {

            "device_id":
                self.device_id,

            "device_type":
                self.device_type,

            "motion":
                motion,

            "motion_detected":
                motion_detected,

            "timestamp":
                timestamp,

            "status":
                mqtt_data.get(
                    "status",
                    "normal"
                ),

            "source":
                "ESP32_PIR"
        }


        # Store latest observation

        self.latest_mqtt_data = data


        return data


    # ========================================================
    # GENERATE DATA
    # ========================================================
    #
    # Retained for compatibility.
    #
    # No random motion is generated anymore.
    # ========================================================

    def generate_data(self):

        if self.latest_mqtt_data is not None:

            return self.latest_mqtt_data.copy()


        return {

            "device_id":
                self.device_id,

            "device_type":
                self.device_type,

            "timestamp":
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "status":
                "waiting_for_mqtt",

            "source":
                "NO_MQTT_DATA"
        }