import time

from devices.base_device import BaseDevice


class TemperatureSensor(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="temperature_sensor",

            # ==================================================
            # RESOURCE CAPABILITY
            # ==================================================

            cpu=0.2,
            ram=0.2,
            battery=0.9,
            bandwidth=0.2,

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

        if "temperature" not in mqtt_data:

            raise ValueError(
                "MQTT data does not contain temperature"
            )


        temperature = mqtt_data[
            "temperature"
        ]

        humidity = mqtt_data.get(
            "humidity"
        )


        timestamp = mqtt_data.get(
            "timestamp"
        )

        if timestamp is None:

            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )


        data = {

            "device_id":
                self.device_id,

            "device_type":
                self.device_type,

            "temperature":
                temperature,

            "humidity":
                humidity,

            "timestamp":
                timestamp,

            "status":
                mqtt_data.get(
                    "status",
                    "normal"
                ),

            "source":
                "ESP32_DHT22"
        }


        # Store latest observation

        self.latest_mqtt_data = data


        return data


    # ========================================================
    # GENERATE DATA
    # ========================================================
    #
    # This method is retained for compatibility with the
    # existing simulator.
    #
    # The new hardware/MQTT mode should use:
    #
    #     update_from_mqtt()
    #
    # ========================================================

    def generate_data(self):

        if self.latest_mqtt_data is not None:

            return self.latest_mqtt_data.copy()


        # Fallback only if MQTT data has not arrived yet

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