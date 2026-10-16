import json
import time


class MQTTDeviceAdapter:
    """
    Converts raw MQTT JSON messages from ESP32/Wokwi devices
    into the normalized observation format used by main.py.

    This class is only an input/adaptation layer.
    It does not make trust, risk, attack, or security decisions.
    """

    DEVICE_TYPE_MAP = {
        "TEMP_001": "temperature_sensor",
        "MOTION_001": "motion_sensor",
        "CLOCK_001": "smart_clock",
        "CAMERA_001": "camera",
    }

    def __init__(self):
        # Latest observation for every device.
        self.latest_observations = {}

        # Diagnostic counters.
        self.message_count = 0
        self.duplicate_message_count = 0
        self.out_of_order_message_count = 0

        # Maximum allowed age for a stored observation.
        self.max_age_seconds = 15

        # Track the most recently accepted identity for devices
        # that send message_id but do not send sequence numbers.
        self.last_message_keys = {}

        # Track sequence state separately for each device.
        # Each value has: {"boot_id": ..., "sequence_number": ...}
        self.last_sequence_state = {}

    # =====================================================
    # DEVICE TYPE
    # =====================================================

    def _get_device_type(self, device_id, supplied_type=None):
        if supplied_type:
            return supplied_type

        return self.DEVICE_TYPE_MAP.get(device_id, "unknown")

    # =====================================================
    # MESSAGE IDENTITY
    # =====================================================

    def _get_message_key(self, data):
        """
        Return an identity for a message when one is supplied.

        A device-generated message_id is preferred. Otherwise,
        use boot_id and sequence_number when available.
        """
        device_id = data.get("device_id")
        message_id = data.get("message_id")

        if message_id is not None:
            return f"{device_id}:id:{message_id}"

        sequence_number = data.get("sequence_number")

        if sequence_number is not None:
            boot_id = data.get("boot_id", "default")
            return (
                f"{device_id}:boot:{boot_id}:"
                f"seq:{sequence_number}"
            )

        # Without an identity field, reliable duplicate detection
        # is not possible. The observation is still accepted.
        return None

    def _check_message_order(self, device_id, data):
        """
        Return (accepted, reason, message_key).

        If sequence_number is present, reject repeated or older
        sequence numbers for the same boot_id. A changed boot_id
        is treated as a device restart and starts a new sequence.

        If only message_id is present, reject an exact repeat of
        the last accepted message_id for that device.
        """
        message_key = self._get_message_key(data)
        sequence_number = data.get("sequence_number")

        if sequence_number is not None:
            # bool is a subclass of int in Python, so reject it
            # explicitly as a sequence number.
            if isinstance(sequence_number, bool) or not isinstance(
                sequence_number, int
            ):
                return False, "invalid_sequence_number", message_key

            boot_id = data.get("boot_id", "default")
            previous = self.last_sequence_state.get(device_id)

            if previous is not None and previous["boot_id"] == boot_id:
                previous_sequence = previous["sequence_number"]

                if sequence_number == previous_sequence:
                    return False, "duplicate", message_key

                if sequence_number < previous_sequence:
                    return False, "out_of_order", message_key

            # Do not update sequence state here. State is updated
            # only after the observation has been constructed.
            return True, None, message_key

        message_id = data.get("message_id")
        if message_id is not None:
            previous_key = self.last_message_keys.get(device_id)

            if message_key == previous_key:
                return False, "duplicate", message_key

        return True, None, message_key

    # =====================================================
    # PROCESS MQTT MESSAGE
    # =====================================================

    def process_message(self, topic, payload):
        # -------------------------------------------------
        # Decode bytes if required
        # -------------------------------------------------

        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                print("[MQTT Adapter] Invalid UTF-8 payload.")
                return None

        if not isinstance(payload, str):
            print("[MQTT Adapter] Payload must be JSON text.")
            return None

        # -------------------------------------------------
        # Parse JSON
        # -------------------------------------------------

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            print(f"[MQTT Adapter] Invalid JSON: {exc}")
            return None

        if not isinstance(data, dict):
            print("[MQTT Adapter] Payload must be a JSON object.")
            return None

        # -------------------------------------------------
        # Device ID
        # -------------------------------------------------

        device_id = data.get("device_id")

        if not device_id:
            print("[MQTT Adapter] Missing device_id.")
            return None

        # -------------------------------------------------
        # Device type
        # -------------------------------------------------

        device_type = self._get_device_type(
            device_id,
            data.get("device_type"),
        )

        # -------------------------------------------------
        # Timestamp
        # -------------------------------------------------

        timestamp = data.get("timestamp")

        if timestamp is None:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # -------------------------------------------------
        # Duplicate and sequence-order check
        # -------------------------------------------------

        accepted, reason, message_key = self._check_message_order(
            device_id, data
        )

        if not accepted:
            if reason == "duplicate":
                self.duplicate_message_count += 1
                print(
                    f"[MQTT DUPLICATE] {device_id}: "
                    f"message {message_key} was already received."
                )
            elif reason == "out_of_order":
                self.out_of_order_message_count += 1
                print(
                    f"[MQTT OUT-OF-ORDER] {device_id}: "
                    f"sequence_number={data.get('sequence_number')} "
                    "is older than the last accepted sequence."
                )
            else:
                print(
                    f"[MQTT Adapter] {device_id}: "
                    "sequence_number must be an integer."
                )

            return None

        # =================================================
        # COMMON OBSERVATION
        # =================================================

        observation = {
            "device_id": device_id,
            "device_type": device_type,
            "timestamp": timestamp,
            "status": data.get("status", "normal"),
            "source": "ESP32_MQTT",
            "mqtt_topic": topic,

            # Keep the original payload for forensic analysis
            # and experiment inspection.
            "raw_data": data,
        }

        observation["message_key"] = message_key

        # =================================================
        # TEMPERATURE SENSOR
        # =================================================

        if device_type == "temperature_sensor":
            observation["temperature"] = data.get("temperature")
            observation["humidity"] = data.get("humidity")

        # =================================================
        # MOTION SENSOR
        # =================================================

        elif device_type == "motion_sensor":
            observation["motion_detected"] = data.get(
                "motion_detected",
                False,
            )

        # =================================================
        # SMART CLOCK
        # =================================================

        elif device_type == "smart_clock":
            observation["hour"] = data.get("hour")
            observation["minute"] = data.get("minute")
            observation["second"] = data.get("second")

        # =================================================
        # CAMERA
        # =================================================

        elif device_type == "camera":
            observation["object_detected"] = data.get(
                "object_detected",
                False,
            )
            observation["fps"] = data.get("fps")
            observation["image_size_bytes"] = data.get(
                "image_size_bytes"
            )

        # =================================================
        # OPTIONAL FUTURE RESOURCE TELEMETRY
        # =================================================

        # These fields are optional. The current ESP32 firmware
        # does not have to send them, but the adapter supports
        # them for future hardware experiments.
        optional_fields = (
            "cpu_usage",
            "ram_usage",
            "battery_level",
            "bandwidth_usage",
            "location",
            "normal_time",
        )

        for field in optional_fields:
            if field in data:
                observation[field] = data[field]

        # Record local reception time separately from the
        # timestamp supplied by the device.
        observation["_received_at_monotonic"] = time.monotonic()
        observation["_received_at_epoch"] = time.time()

        # =================================================
        # UPDATE MESSAGE STATE AND STORE OBSERVATION
        # =================================================

        sequence_number = data.get("sequence_number")

        if sequence_number is not None:
            self.last_sequence_state[device_id] = {
                "boot_id": data.get("boot_id", "default"),
                "sequence_number": sequence_number,
            }
        elif data.get("message_id") is not None:
            self.last_message_keys[device_id] = message_key

        self.latest_observations[device_id] = observation
        self.message_count += 1

        return observation

    # =====================================================
    # GET LATEST OBSERVATION
    # =====================================================

    def get_latest_observation(self, device_id):
        observation = self.latest_observations.get(device_id)

        if observation is None:
            return None

        return observation.copy()

    # =====================================================
    # GET FRESH OBSERVATION
    # =====================================================

    def get_fresh_observation(self, device_id, max_age_seconds=None):
        observation = self.latest_observations.get(device_id)

        if observation is None:
            return None

        if max_age_seconds is None:
            max_age_seconds = self.max_age_seconds

        received_at = observation.get("_received_at_monotonic")

        if received_at is None:
            return None

        age_seconds = time.monotonic() - received_at

        if age_seconds > max_age_seconds:
            print(
                f"[MQTT STALE] {device_id}: "
                f"last message is {age_seconds:.1f}s old "
                f"(limit={max_age_seconds}s)."
            )
            return None

        result = observation.copy()
        result["message_age_seconds"] = round(age_seconds, 2)

        return result

    # =====================================================
    # GET ALL OBSERVATIONS
    # =====================================================

    def get_all_observations(self):
        return {
            device_id: observation.copy()
            for device_id, observation in self.latest_observations.items()
        }

    # =====================================================
    # CHECK OBSERVATION AVAILABILITY
    # =====================================================

    def has_observation(self, device_id):
        return device_id in self.latest_observations

    # =====================================================
    # MESSAGE COUNT
    # =====================================================

    def get_message_count(self):
        return self.message_count

    def get_duplicate_message_count(self):
        return self.duplicate_message_count

    def get_out_of_order_message_count(self):
        return self.out_of_order_message_count
