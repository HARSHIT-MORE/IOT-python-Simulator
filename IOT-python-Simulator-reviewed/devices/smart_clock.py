import time

from devices.base_device import BaseDevice


class SmartClock(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="smart_clock",

            # ==================================================
            # RESOURCE CAPABILITY
            # ==================================================

            cpu=0.5,
            ram=0.5,
            battery=0.7,
            bandwidth=0.5,

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

        if "hour" not in mqtt_data:

            raise ValueError(
                "MQTT data does not contain hour"
            )


        hour = mqtt_data.get(
            "hour"
        )

        minute = mqtt_data.get(
            "minute",
            0
        )

        second = mqtt_data.get(
            "second",
            0
        )


        timestamp = mqtt_data.get(
            "timestamp"
        )

        if timestamp is None:

            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )


        # ----------------------------------------------------
        # Construct readable time
        # ----------------------------------------------------

        current_time = (
            f"{int(hour):02d}:"
            f"{int(minute):02d}:"
            f"{int(second):02d}"
        )


        data = {

            "device_id":
                self.device_id,

            "device_type":
                self.device_type,

            "time":
                current_time,

            "hour":
                int(hour),

            "minute":
                int(minute),

            "second":
                int(second),

            "timestamp":
                timestamp,

            "status":
                mqtt_data.get(
                    "status",
                    "normal"
                ),

            "source":
                "ESP32_NTP_CLOCK"
        }


        self.latest_mqtt_data = data


        return data


    # ========================================================
    # GENERATE DATA
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