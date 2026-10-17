"""Device-specific attack/anomaly checks based on actual MQTT readings.

This module intentionally separates an anomaly from a confirmed attack:
physical sensor anomalies can also be caused by faults or environmental changes.
Thresholds are explicit configurable heuristics and must be validated against
real deployment data before being presented as optimal research parameters.
"""
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import math
import time


class DeviceAttackDetector:
    # Configurable initial thresholds. These are engineering starting points,
    # not universally valid thresholds; calibrate using normal device traces.
    TEMPERATURE_MIN_C = -40.0       # DHT22 nominal operating measurement range
    TEMPERATURE_MAX_C = 80.0
    HUMIDITY_MIN_PCT = 0.0
    HUMIDITY_MAX_PCT = 100.0
    # Calibrate these per device type using normal deployment traces.
    TEMPERATURE_LIMITS = {
        "temperature_sensor": {"max_change_c": 5.0, "max_change_c_per_second": 0.5},
    }
    CLOCK_DRIFT_TOLERANCE_SECONDS = 120
    DEVICE_UTC_OFFSET_SECONDS = 19800  # ESP32 firmware GMT_OFFSET=+05:30
    CAMERA_FPS_MIN = 1
    CAMERA_FPS_MAX = 30              # matches this Wokwi camera simulator
    CAMERA_SIZE_MIN_BYTES = 1000
    CAMERA_SIZE_MAX_BYTES = 250000
    CAMERA_BASELINE_MIN_SAMPLES = 5
    CAMERA_SIZE_MEDIAN_FACTOR = 3.0
    MOTION_WINDOW_SECONDS = 60
    MOTION_MAX_RISING_EDGES = 6      # >6 rising edges in 60 s is suspicious
    MAX_BEHAVIOR_PENALTY = 1.0

    # Penalties reflect relative severity ordering, not fitted optimums.
    PENALTIES = {
        "UNAUTHORIZED_COMMAND": 0.35,
        "UNEXPECTED_NETWORK_DESTINATION": 0.25,
        "TEMPERATURE_RATE_ANOMALY": 0.30,
        "TEMPERATURE_RANGE_ANOMALY": 0.25,
        "HUMIDITY_RANGE_ANOMALY": 0.20,
        "MOTION_EVENT_BURST": 0.20,
        "CLOCK_DRIFT": 0.30,
        "CAMERA_FPS_ANOMALY": 0.20,
        "CAMERA_PAYLOAD_SIZE_ANOMALY": 0.20,
        "INVALID_DEVICE_SCHEMA": 0.35,
        "DEVICE_HMAC_FAILURE": 0.50,
        "INVALID_STATUS": 0.15,
    }

    ALLOWED_DESTINATIONS = {
        # Configure real destinations here if firmware starts reporting them.
        "TEMP_001": set(), "MOTION_001": set(),
        "CLOCK_001": set(), "CAMERA_001": set(),
    }

    def __init__(self):
        self.last_temperature = {}
        self.last_temperature_time = {}
        self.camera_sizes = defaultdict(lambda: deque(maxlen=31))
        self.motion_events = defaultdict(lambda: deque())
        self.last_motion_state = {}
        self.last_clock_value = {}
        self.incidents = []
        self.observation_count = defaultdict(int)

    @staticmethod
    def _indicator(attack_type, condition, observed, threshold, penalty,
                   classification="ANOMALY", confirmed=False):
        return {
            "attack_type": attack_type,
            "condition": condition,
            "observed": observed,
            "threshold": threshold,
            "penalty": round(float(penalty), 3),
            "classification": classification,
            "confirmed": bool(confirmed),
        }

    @staticmethod
    def _as_number(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not math.isfinite(float(value)):
            return None
        return float(value)

    def analyze(self, observation):
        device_id = observation.get("device_id", "UNKNOWN")
        device_type = observation.get("device_type", "unknown")
        raw = observation.get("raw_data")
        if not isinstance(raw, dict):
            raw = observation
        now = time.time()
        indicators = []
        confirmed_attack = False

        def add(name, condition, observed, threshold, classification="ANOMALY", confirmed=False):
            nonlocal confirmed_attack
            indicators.append(self._indicator(
                name, condition, observed, threshold,
                self.PENALTIES.get(name, 0.15), classification, confirmed
            ))
            confirmed_attack = confirmed_attack or confirmed

        self.observation_count[device_id] += 1

        # Generic policy checks only run when the device actually reports these fields.
        # The current Wokwi firmware does not report commands or destination endpoints.
        command = raw.get("command")
        if command is not None and raw.get("command_authorized") is False:
            add("UNAUTHORIZED_COMMAND",
                "A command was present but command_authorized is false",
                command, "command_authorized == true", "POLICY_VIOLATION", True)

        destination = raw.get("destination_ip", raw.get("destination"))
        allowed = self.ALLOWED_DESTINATIONS.get(device_id, set())
        if destination is not None and allowed and destination not in allowed:
            add("UNEXPECTED_NETWORK_DESTINATION",
                "Reported destination is not in this device's configured allowlist",
                destination, sorted(allowed), "POLICY_VIOLATION", True)

        # Only trust a device-origin verification result if it was supplied by
        # the adapter after verifying a signature actually present in the MQTT payload.
        # Do not use main.py's gateway-generated authentication_status here.
        device_hmac_valid = raw.get("device_hmac_valid")
        if device_hmac_valid is False:
            add("DEVICE_HMAC_FAILURE",
                "Device-origin message authentication failed; tampering is possible but not proven",
                False, True, "INTEGRITY_FAILURE", False)

        status = raw.get("status")
        if status is not None and status not in {"normal", "motion_detected"}:
            add("INVALID_STATUS", "Status is not in the device's expected status set",
                status, ["normal", "motion_detected"], "SCHEMA_ANOMALY", False)

        if device_type == "temperature_sensor":
            temp = self._as_number(raw.get("temperature", observation.get("temperature")))
            humidity = self._as_number(raw.get("humidity", observation.get("humidity")))
            if temp is None:
                add("INVALID_DEVICE_SCHEMA", "Temperature reading is missing or non-numeric",
                    raw.get("temperature"), "finite numeric temperature", "SCHEMA_ANOMALY", False)
            else:
                if not self.TEMPERATURE_MIN_C <= temp <= self.TEMPERATURE_MAX_C:
                    add("TEMPERATURE_RANGE_ANOMALY",
                        "Measured temperature is outside the configured DHT22 measurement range",
                        temp, [self.TEMPERATURE_MIN_C, self.TEMPERATURE_MAX_C], "SENSOR_ANOMALY", False)
                previous = self.last_temperature.get(device_id)
                received_at = self._as_number(observation.get("_received_at_monotonic"))
                if received_at is None:
                    received_at = self._as_number(observation.get("_received_at_epoch"))
                if received_at is None:
                    received_at = now
                previous_at = self.last_temperature_time.get(device_id)
                limits = self.TEMPERATURE_LIMITS.get(device_type, {})
                max_step = float(limits.get("max_change_c", 5.0))
                max_rate = float(limits.get("max_change_c_per_second", 0.5))
                if previous is not None and previous_at is not None:
                    delta = abs(temp - previous)
                    elapsed = max(0.0, received_at - previous_at)
                    rate = delta / elapsed if elapsed > 0 else (float("inf") if delta else 0.0)
                    if delta > max_step or rate > max_rate:
                        add("TEMPERATURE_RATE_ANOMALY",
                            "Temperature change exceeds the configured device-type step or elapsed-time rate limit",
                            {"change_c": round(delta, 3), "elapsed_seconds": round(elapsed, 3),
                             "rate_c_per_second": round(rate, 3) if math.isfinite(rate) else "infinite"},
                            {"max_change_c": max_step, "max_change_c_per_second": max_rate},
                            "POSSIBLE_FALSE_DATA_INJECTION", False)
                self.last_temperature[device_id] = temp
                self.last_temperature_time[device_id] = received_at
            if humidity is None or not self.HUMIDITY_MIN_PCT <= humidity <= self.HUMIDITY_MAX_PCT:
                add("HUMIDITY_RANGE_ANOMALY",
                    "Humidity is missing, non-numeric, or outside 0-100 percent",
                    raw.get("humidity"), [self.HUMIDITY_MIN_PCT, self.HUMIDITY_MAX_PCT], "SENSOR_ANOMALY", False)

        elif device_type == "motion_sensor":
            motion = raw.get("motion_detected", observation.get("motion_detected"))
            if not isinstance(motion, bool):
                add("INVALID_DEVICE_SCHEMA", "motion_detected must be a JSON boolean",
                    motion, "true or false", "SCHEMA_ANOMALY", False)
            else:
                previous = self.last_motion_state.get(device_id)
                # Count rising edges only; repeated TRUE samples are not new events.
                if motion and previous is False:
                    q = self.motion_events[device_id]
                    q.append(now)
                self.last_motion_state[device_id] = motion
                q = self.motion_events[device_id]
                while q and now - q[0] > self.MOTION_WINDOW_SECONDS:
                    q.popleft()
                if len(q) > self.MOTION_MAX_RISING_EDGES:
                    add("MOTION_EVENT_BURST",
                        "More than the configured number of rising edges occurred in the rolling window",
                        len(q), f"<= {self.MOTION_MAX_RISING_EDGES} rising edges / {self.MOTION_WINDOW_SECONDS} s",
                        "POSSIBLE_SENSOR_CHATTER_OR_FALSE_EVENT_INJECTION", False)

        elif device_type == "smart_clock":
            hour = raw.get("hour", observation.get("hour"))
            minute = raw.get("minute", observation.get("minute"))
            second = raw.get("second", observation.get("second"))
            if any(isinstance(v, bool) or not isinstance(v, int) for v in (hour, minute, second)) or not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
                add("INVALID_DEVICE_SCHEMA", "Clock hour/minute/second fields are invalid",
                    [hour, minute, second], "hour 0-23; minute/second 0-59", "SCHEMA_ANOMALY", False)
            else:
                clock_seconds = hour * 3600 + minute * 60 + second

                # Prefer a device-origin Unix timestamp when firmware supplies one.
                # Do NOT use observation["timestamp"] here: the MQTT adapter may
                # create that timestamp at the gateway, which cannot prove device time.
                device_epoch = self._as_number(raw.get("device_timestamp_epoch"))
                if device_epoch is not None:
                    # Prefer the device-origin epoch timestamp, which is covered
                    # by HMAC in the current firmware.
                    delta = abs(now - device_epoch)
                    comparison_mode = "device Unix timestamp vs gateway Unix time"
                    threshold_description = (
                        f"absolute epoch difference <= {self.CLOCK_DRIFT_TOLERANCE_SECONDS} seconds"
                    )
                elif raw.get("device_hmac_valid") is not True:
                    # A legacy/unsigned clock payload has neither an authenticated
                    # epoch timestamp nor trustworthy date/timezone metadata.
                    # Do not label its time-of-day difference as clock drift; the
                    # gateway separately rejects/unverifies the message integrity.
                    self.last_clock_value[device_id] = clock_seconds
                    delta = None
                else:
                    # Compatibility fallback for signed legacy devices that do
                    # not yet include an epoch. This is only a time-of-day check,
                    # not proof of tampering, and should be retired once all
                    # firmware versions send device_timestamp_epoch.
                    device_tz = timezone(timedelta(seconds=self.DEVICE_UTC_OFFSET_SECONDS))
                    reference_now = datetime.fromtimestamp(now, timezone.utc).astimezone(device_tz)
                    reference_seconds = (
                        reference_now.hour * 3600
                        + reference_now.minute * 60
                        + reference_now.second
                    )
                    delta = abs(clock_seconds - reference_seconds)
                    delta = min(delta, 86400 - delta)
                    offset_hours = self.DEVICE_UTC_OFFSET_SECONDS / 3600
                    offset_sign = "+" if offset_hours >= 0 else ""
                    offset_label = f"UTC{offset_sign}{offset_hours:g}"
                    comparison_mode = f"time-of-day vs configured {offset_label} reference"
                    threshold_description = (
                        f"circular time-of-day difference <= {self.CLOCK_DRIFT_TOLERANCE_SECONDS} seconds "
                        f"under the configured {offset_label} timezone assumption"
                    )

                if delta is not None and delta > self.CLOCK_DRIFT_TOLERANCE_SECONDS:
                    add(
                        "CLOCK_DRIFT",
                        "Clock difference exceeds tolerance when compared using "
                        f"{comparison_mode}; because device date/timezone metadata may be absent, "
                        "timezone/configuration error, stale telemetry, or clock fault must be ruled out "
                        "before attributing the anomaly to an attack",
                        round(delta, 3), threshold_description,
                        "CLOCK_ANOMALY_POSSIBLE_TIME_MANIPULATION", False
                    )
                self.last_clock_value[device_id] = clock_seconds

        elif device_type == "camera":
            fps = self._as_number(raw.get("fps", observation.get("fps")))
            size = self._as_number(raw.get("image_size_bytes", observation.get("image_size_bytes")))
            if fps is None or not self.CAMERA_FPS_MIN <= fps <= self.CAMERA_FPS_MAX:
                add("CAMERA_FPS_ANOMALY", "Camera FPS is missing or outside configured simulator range",
                    raw.get("fps"), [self.CAMERA_FPS_MIN, self.CAMERA_FPS_MAX], "CAMERA_TELEMETRY_ANOMALY", False)
            if size is None or not self.CAMERA_SIZE_MIN_BYTES <= size <= self.CAMERA_SIZE_MAX_BYTES:
                add("CAMERA_PAYLOAD_SIZE_ANOMALY", "Image metadata size is missing or outside configured simulator range",
                    raw.get("image_size_bytes"), [self.CAMERA_SIZE_MIN_BYTES, self.CAMERA_SIZE_MAX_BYTES], "CAMERA_TELEMETRY_ANOMALY", False)
            elif len(self.camera_sizes[device_id]) >= self.CAMERA_BASELINE_MIN_SAMPLES:
                baseline = sorted(self.camera_sizes[device_id])
                median = baseline[len(baseline) // 2]
                if median > 0 and (size > median * self.CAMERA_SIZE_MEDIAN_FACTOR or size < median / self.CAMERA_SIZE_MEDIAN_FACTOR):
                    add("CAMERA_PAYLOAD_SIZE_ANOMALY",
                        "Image metadata size differs from the historical median by more than the configured factor",
                        int(size), f"median={int(median)} bytes; ratio within 1/{self.CAMERA_SIZE_MEDIAN_FACTOR}..{self.CAMERA_SIZE_MEDIAN_FACTOR}",
                        "POSSIBLE_CAMERA_DATA_ANOMALY", False)
            if size is not None and self.CAMERA_SIZE_MIN_BYTES <= size <= self.CAMERA_SIZE_MAX_BYTES:
                self.camera_sizes[device_id].append(size)

        # Physical telemetry outliers and HMAC failures remain unconfirmed attacks.
        # An HMAC failure proves that authentication/integrity verification failed,
        # but key/configuration or serialization problems can cause the same result.
        # Only explicit policy violations are marked confirmed by the current rules.
        total_penalty = min(self.MAX_BEHAVIOR_PENALTY, sum(i["penalty"] for i in indicators))
        behavior_score = max(0.0, 1.0 - total_penalty)
        result = {
            "device_id": device_id,
            "observation_number": self.observation_count[device_id],
            "indicators": indicators,
            "penalty_total": round(total_penalty, 3),
            "behavior_score": round(behavior_score, 3),
            "anomaly_detected": bool(indicators),
            "confirmed_attack": confirmed_attack,
            "attack_type": indicators[0]["attack_type"] if indicators else None,
            "timestamp_epoch": now,
            "temperature_thresholds": self.TEMPERATURE_LIMITS.get(device_type),
        }
        if indicators:
            self.incidents.append({
                "device_id": device_id,
                "attack_type": result["attack_type"],
                "description": "; ".join(i["condition"] for i in indicators),
                "evidence": indicators,
                "confirmed_attack": confirmed_attack,
                "classification": "CONFIRMED_POLICY_VIOLATION" if confirmed_attack else "ANOMALY_REQUIRES_INVESTIGATION",
                "timestamp_epoch": now,
            })
        return result

    def get_incidents(self):
        return list(self.incidents)
