import time

from devices.base_device import BaseDevice


class Camera(BaseDevice):

    def __init__(self, device_id):

        super().__init__(
            device_id=device_id,
            device_type="camera",

            # ==================================================
            # RESOURCE CAPABILITY
            # ==================================================

            cpu=0.8,
            ram=0.8,
            battery=0.6,
            bandwidth=0.8,

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

        object_detected = mqtt_data.get(
            "object_detected",
            False
        )

        fps = mqtt_data.get(
            "fps",
            0
        )

        image_size_bytes = mqtt_data.get(
            "image_size_bytes",
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
        # Determine event
        # ----------------------------------------------------

        if object_detected:

            event = "person_detected"

        else:

            event = "no_person"


        data = {

            "device_id":
                self.device_id,

            "device_type":
                self.device_type,

            "event":
                event,

            "object_detected":
                object_detected,

            "fps":
                fps,

            "image_size_bytes":
                image_size_bytes,

            "timestamp":
                timestamp,

            "status":
                mqtt_data.get(
                    "status",
                    "normal"
                ),

            "source":
                "CAMERA_MQTT"
        }


        self.latest_mqtt_data = data


        return data


    # ========================================================
    # GENERATE DATA
    # ========================================================
    #
    # No random camera events are generated anymore.
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