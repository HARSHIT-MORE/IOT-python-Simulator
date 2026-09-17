import time


class ContextAnalyzer:

    def __init__(self):

        # Initial weights
        self.location_weight = 0.40
        self.time_weight = 0.30
        self.resource_weight = 0.30

    # ==========================================================
    # LOCATION ANALYSIS
    # ==========================================================

    def analyze_location(self, data, device):

        current_location = data.get(
            "location",
            device.location
        )

        expected_location = device.location

        if current_location == expected_location:
            return 1.0

        return 0.0

    # ==========================================================
    # TIME ANALYSIS
    # ==========================================================

    def analyze_time(self, device):

        current_hour = time.localtime().tm_hour

        normal_time = device.normal_time

        try:

            start_time, end_time = (
                normal_time.split("-")
            )

            start_hour = int(
                start_time.split(":")[0]
            )

            end_hour = int(
                end_time.split(":")[0]
            )

            if start_hour <= current_hour <= end_hour:
                return 1.0

            return 0.0

        except (ValueError, AttributeError):

            # If the configured time range cannot
            # be interpreted, use a neutral value.
            return 0.5

    # ==========================================================
    # REQUESTED RESOURCE ANALYSIS
    # ==========================================================

    def analyze_requested_resource(
        self,
        data,
        device
    ):

        requested_resource = data.get(
            "requested_resource",
            "sensor_data"
        )

        # ------------------------------------------------------
        # Resources normally associated with each device
        # ------------------------------------------------------

        normal_resources = {

            "smart_clock": [
                "sensor_data",
                "time_data"
            ],

            "temperature_sensor": [
                "sensor_data"
            ],

            "motion_sensor": [
                "sensor_data"
            ],

            "camera": [
                "sensor_data",
                "image_data"
            ]
        }

        allowed_resources = normal_resources.get(
            device.device_type,
            ["sensor_data"]
        )

        if requested_resource in allowed_resources:
            return 1.0

        return 0.0

    # ==========================================================
    # CONTEXT SCORE
    # ==========================================================

    def calculate_context_score(
        self,
        data,
        device
    ):

        location_score = (
            self.analyze_location(
                data,
                device
            )
        )

        time_score = (
            self.analyze_time(
                device
            )
        )

        resource_score = (
            self.analyze_requested_resource(
                data,
                device
            )
        )

        context_score = (

            self.location_weight * location_score

            + self.time_weight * time_score

            + self.resource_weight * resource_score
        )

        return round(
            context_score,
            3
        )

    # ==========================================================
    # CONTEXT STATUS
    # ==========================================================

    def get_context_status(
        self,
        context_score
    ):

        if context_score >= 0.80:

            return "NORMAL"

        elif context_score >= 0.60:

            return "SLIGHTLY_ABNORMAL"

        elif context_score >= 0.40:

            return "SUSPICIOUS"

        else:

            return "HIGHLY_ABNORMAL"

    # ==========================================================
    # COMPLETE ANALYSIS
    # ==========================================================

    def analyze(
        self,
        data,
        device
    ):

        location_score = (
            self.analyze_location(
                data,
                device
            )
        )

        time_score = (
            self.analyze_time(
                device
            )
        )

        resource_score = (
            self.analyze_requested_resource(
                data,
                device
            )
        )

        context_score = (
            self.calculate_context_score(
                data,
                device
            )
        )

        context_status = (
            self.get_context_status(
                context_score
            )
        )

        return {

            "location_score":
                round(location_score, 3),

            "time_score":
                round(time_score, 3),

            "resource_score":
                round(resource_score, 3),

            "context_score":
                context_score,

            "context_status":
                context_status
        }