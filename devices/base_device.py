import random


class BaseDevice:

    def __init__(
        self,
        device_id,
        device_type,
        cpu,
        ram,
        battery,
        bandwidth,
        location,
        normal_time
    ):

        self.device_id = device_id
        self.device_type = device_type

        # ==========================================================
        # RESOURCE CAPABILITY
        # ==========================================================

        self.cpu = cpu
        self.ram = ram
        self.battery = battery
        self.bandwidth = bandwidth

        # ==========================================================
        # CONTEXT
        # ==========================================================

        self.location = location
        self.normal_time = normal_time

        # ==========================================================
        # INITIAL TRUST
        # ==========================================================

        self.trust_score = 0.95

        # ==========================================================
        # CURRENT RESOURCE UTILIZATION
        # ==========================================================

        self.cpu_usage = 0.0
        self.ram_usage = 0.0
        self.bandwidth_usage = 0.0

        # ==========================================================
        # CURRENT BATTERY LEVEL
        # ==========================================================

        self.battery_level = battery

        # ==========================================================
        # LATEST MQTT OBSERVATION
        # ==========================================================

        self.latest_mqtt_data = None


    # ==========================================================
    # RESOURCE PROFILE
    # ==========================================================

    def get_resource_profile(self):

        return {

            "cpu": self.cpu,

            "ram": self.ram,

            "battery": self.battery,

            "bandwidth": self.bandwidth
        }


    # ==========================================================
    # CONTEXT PROFILE
    # ==========================================================

    def get_context_profile(self):

        return {

            "location":
                self.location,

            "normal_time":
                self.normal_time
        }


    # ==========================================================
    # CURRENT RESOURCE USAGE
    # ==========================================================

    def update_resource_usage(self):

        # ------------------------------------------------------
        # Until ESP32 resource telemetry is implemented,
        # resource utilization is estimated locally.
        # ------------------------------------------------------

        self.cpu_usage = round(
            random.uniform(0.1, 0.9),
            3
        )

        self.ram_usage = round(
            random.uniform(0.1, 0.9),
            3
        )

        self.bandwidth_usage = round(
            random.uniform(0.1, 0.9),
            3
        )

        # Simulate gradual battery consumption

        battery_drop = random.uniform(
            0.001,
            0.01
        )

        self.battery_level = max(
            0.0,
            self.battery_level - battery_drop
        )


    # ==========================================================
    # CURRENT RESOURCE STATE
    # ==========================================================

    def get_current_resource_state(self):

        return {

            "cpu_usage":
                self.cpu_usage,

            "ram_usage":
                self.ram_usage,

            "battery_level":
                round(
                    self.battery_level,
                    3
                ),

            "bandwidth_usage":
                self.bandwidth_usage
        }


    # ==========================================================
    # CURRENT CONTEXT
    # ==========================================================

    def get_current_context(self):

        return {

            "location":
                self.location,

            "requested_resource":
                "sensor_data"
        }


    # ==========================================================
    # UPDATE FROM MQTT
    # ==========================================================

    def update_from_mqtt(self, mqtt_data):

        if not isinstance(mqtt_data, dict):

            raise ValueError(
                "MQTT data must be a dictionary"
            )

        self.latest_mqtt_data = mqtt_data

        return mqtt_data


    # ==========================================================
    # GET LATEST MQTT DATA
    # ==========================================================

    def get_latest_mqtt_data(self):

        return self.latest_mqtt_data