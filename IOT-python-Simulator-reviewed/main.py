import time
import json
import threading
import paho.mqtt.client as mqtt

from iot.mqtt_adapter import MQTTDeviceAdapter





# ============================================================

# DEVICE IMPORTS

# ============================================================



from devices.smart_clock import SmartClock



from devices.temperature_sensor import TemperatureSensor



from devices.motion_sensor import MotionSensor



from devices.camera import Camera





# ============================================================

# EDGE IMPORT

# ============================================================



from edge.raspberry_pi import RaspberryPi





# ============================================================

# GATEWAY IMPORTS

# ============================================================



from gateway.gateway import Gateway



from gateway.trust_manager import TrustManager



from gateway.resource_manager import ResourceManager



from gateway.behavior_analyzer import BehaviorAnalyzer



from gateway.context_analyzer import ContextAnalyzer



from gateway.history_manager import HistoryManager



from gateway.risk_engine import RiskEngine



from gateway.adaptive_weight_engine import AdaptiveWeightEngine



from gateway.trust_engine import TrustEngine



from gateway.decision_engine import DecisionEngine





# ============================================================

# SECURITY IMPORTS

# ============================================================



from security.device_attack_detector import DeviceAttackDetector



from security.evidence_collector import EvidenceCollector



from security.crypto import LightweightCrypto





# ============================================================

# EXPERIMENT IMPORTS

# ============================================================



from experiments.metrics import SecurityMetrics
from experiments.attack_visualizer import ExperimentVisualizer





# ============================================================

# INITIALIZE MANAGERS

# ============================================================



trust_manager = TrustManager()



resource_manager = ResourceManager()



behavior_analyzer = BehaviorAnalyzer()



context_analyzer = ContextAnalyzer()



history_manager = HistoryManager()



risk_engine = RiskEngine()



adaptive_weight_engine = AdaptiveWeightEngine()



trust_engine = TrustEngine()



decision_engine = DecisionEngine()



device_attack_detector = DeviceAttackDetector()
last_processed_observation_keys = {}



evidence_collector = EvidenceCollector()



crypto = LightweightCrypto()





# ============================================================

# INITIALIZE METRICS

# ============================================================



metrics = SecurityMetrics()
visualizer = ExperimentVisualizer()





# ============================================================

# INITIALIZE RASPBERRY PI

# ============================================================



raspberry_pi = RaspberryPi()





# ============================================================

# INITIALIZE GATEWAY

# ============================================================



gateway = Gateway(



    trust_manager=trust_manager,



    evidence_collector=evidence_collector,



    crypto=crypto,



    history_manager=history_manager

)





# ============================================================

# CREATE IOT DEVICES

# ============================================================



devices = [



    SmartClock(

        device_id="CLOCK_001"

    ),



    TemperatureSensor(

        device_id="TEMP_001"

    ),



    MotionSensor(

        device_id="MOTION_001"

    ),



    Camera(

        device_id="CAMERA_001"

    )



]





# ============================================================

# REGISTER DEVICES

# ============================================================



for device in devices:



    trust_manager.register_device(



        device.device_id,



        initial_score=0.95

    )



    history_manager.register_device(



        device.device_id

    )





# ============================================================
# LIVE DEVICE TELEMETRY CONFIGURATION
# ============================================================

# The loop processes only new MQTT observations. No attack is
# declared merely because a round number has been reached.
TOTAL_ROUNDS = 15
LIVE_TELEMETRY_ONLY = True


# ============================================================

# START SIMULATION

# ============================================================



print("\n")



print("=" * 80)



print(

    "       ADAPTIVE RESOURCE-AWARE ZERO-TRUST IoT SIMULATION"

)



print("=" * 80)



print(f"\nLive telemetry rounds     : {TOTAL_ROUNDS}")
print("Attack labels             : derived from observed evidence; no scheduled attack injection")



print("=" * 80)





# ============================================================
# MQTT CONFIGURATION
# ============================================================

MQTT_BROKER = "test.mosquitto.org"
MQTT_PORT = 1883

# Subscribe to all ESP32/Wokwi device topics.
MQTT_TOPIC = "harshit/iot/#"


# ============================================================
# MQTT ADAPTER
# ============================================================

# Stores the latest observation for every ESP32 device.
mqtt_adapter = MQTTDeviceAdapter()


def wait_for_new_observation(device_id, previous_key, timeout_seconds=12):
    """Wait for a fresh MQTT message with a new device-generated identity."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        candidate = mqtt_adapter.get_fresh_observation(device_id)
        if candidate is not None:
            key = candidate.get("message_key") or candidate.get("_received_at_monotonic")
            if key is not None and key != previous_key:
                return candidate
        time.sleep(0.2)
    return None



# ============================================================
# MQTT CALLBACKS
# ============================================================

def mqtt_on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties
):

    global mqtt_connected

    if reason_code == 0:

        mqtt_connected = True

        print(
            "\n[MQTT] Connected to MQTT broker"
        )

        client.subscribe(
            MQTT_TOPIC
        )

        print(
            f"[MQTT] Subscribed to: {MQTT_TOPIC}"
        )

    else:

        print(
            f"[MQTT] Connection failed: {reason_code}"
        )


def mqtt_on_message(
    client,
    userdata,
    msg
):

    payload = msg.payload.decode(
        "utf-8",
        errors="replace"
    )

    print(
        f"\n[MQTT] Message received | Topic: {msg.topic}"
    )

    print(
        f"[MQTT] Payload: {payload}"
    )

    # The adapter requires both the MQTT topic and payload.
    observation = mqtt_adapter.process_message(
        msg.topic,
        payload
    )

    if observation is None:
        print("[MQTT] Adapter rejected the observation.")
        return

    # A real device packet has reached the Python input layer.
    mqtt_message_event.set()

    device_id = observation.get(
        "device_id",
        "UNKNOWN"
    )

    device_type = observation.get(
        "device_type",
        "unknown"
    )

    # Record that this real device has produced at least one
    # accepted MQTT observation. This is used only for startup
    # synchronization, never for trust/risk/decision logic.
    if device_id in EXPECTED_MQTT_DEVICES:
        # Startup synchronization requires a verifiable device-origin message.
        # An unsigned/stale publisher on the public test broker must not satisfy
        # the readiness condition merely by reusing an expected device_id.
        if observation.get("device_hmac_valid") is True:
            received_mqtt_devices.add(device_id)
        else:
            print(
                f"[MQTT STARTUP] {device_id} message is not HMAC-verified; "
                "waiting for an authenticated device reading."
            )

        if received_mqtt_devices >= EXPECTED_MQTT_DEVICES:
            all_expected_devices_event.set()

    print(
        f"\n[MQTT] New observation: "
        f"{device_id} ({device_type})"
    )

    if device_type == "temperature_sensor":

        print(
            f"[MQTT] Temperature: "
            f"{observation.get('temperature')} °C"
        )

        print(
            f"[MQTT] Humidity: "
            f"{observation.get('humidity')} %"
        )

    elif device_type == "motion_sensor":

        print(
            f"[MQTT] Motion: "
            f"{observation.get('motion_detected')}"
        )

    elif device_type == "smart_clock":

        print(
            f"[MQTT] Time: "
            f"{observation.get('hour')}:"
            f"{observation.get('minute')}:"
            f"{observation.get('second')}"
        )

    elif device_type == "camera":

        print(
            f"[MQTT] Object detected: "
            f"{observation.get('object_detected')}"
        )

        print(
            f"[MQTT] FPS: "
            f"{observation.get('fps')}"
        )

        print(
            f"[MQTT] Image size: "
            f"{observation.get('image_size_bytes')} bytes"
        )


# ============================================================
# MQTT CLIENT
# ============================================================

mqtt_client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2
)

mqtt_client.on_connect = mqtt_on_connect
mqtt_client.on_message = mqtt_on_message

# MQTT is the external device-input layer. The existing
# behavior, context, history, risk, adaptive-weight, trust,
# decision, forensic, and recovery pipeline remains intact.
#
# HMAC generation is still performed by the existing crypto
# module after the MQTT observation is received. This keeps
# compatibility with the current simulator architecture.
#
# For a future true end-to-end hardware experiment, the ESP32
# should generate its own HMAC and the gateway should verify
# that device-generated signature instead of re-signing data.
# MQTT connection state.
mqtt_connected = False
mqtt_connected_event = threading.Event()
mqtt_message_event = threading.Event()

# Devices expected from the combined ESP32/Wokwi sketch.
EXPECTED_MQTT_DEVICES = {
    "TEMP_001",
    "MOTION_001",
    "CLOCK_001",
    "CAMERA_001"
}

received_mqtt_devices = set()
all_expected_devices_event = threading.Event()

# Real-hardware mode: do not silently replace missing MQTT data
# with generated simulator data.
REQUIRE_MQTT_DATA = True

# Startup controls.
MQTT_CONNECT_TIMEOUT = 60
MQTT_FIRST_MESSAGE_TIMEOUT = 60
MQTT_ALL_DEVICES_TIMEOUT = 60
MQTT_RETRY_DELAY = 2


# ============================================================
# MQTT STARTUP
# ============================================================

def wait_for_mqtt_ready(timeout_seconds=MQTT_CONNECT_TIMEOUT):
    """
    Wait until the MQTT on_connect callback confirms that the
    broker connection and subscription are ready.

    If the connection is not ready within the timeout, retry the
    MQTT connection instead of starting the experiment early.
    """

    global mqtt_connected

    deadline = time.time() + timeout_seconds

    while not mqtt_connected and time.time() < deadline:
        mqtt_connected_event.wait(timeout=0.5)

    if mqtt_connected:
        print("[MQTT] MQTT input layer is ready.")
        return True

    print(
        "[MQTT] MQTT connection did not become ready within "
        f"{timeout_seconds} seconds."
    )
    return False


def wait_for_first_mqtt_message(timeout_seconds=MQTT_FIRST_MESSAGE_TIMEOUT):
    """Wait for at least one actual ESP32/Wokwi MQTT message."""

    print(
        "[MQTT] Waiting for the first ESP32/Wokwi observation "
        f"(timeout={timeout_seconds}s)..."
    )

    if mqtt_message_event.wait(timeout_seconds):
        print("[MQTT] First real device observation received.")
        return True

    print("\n" + "=" * 80)
    print("[MQTT ERROR] No MQTT device message was received.")
    print("=" * 80)
    print("Check:")
    print("  1. Wokwi ESP32 simulation is RUNNING.")
    print("  2. ESP32 shows 'MQTT connected!'.")
    print("  3. ESP32 shows 'MQTT message sent:'.")
    print("  4. The topic starts with: harshit/iot/")
    print("  5. Wokwi and Python main.py run at the same time.")
    print("=" * 80)
    return False


def wait_for_all_expected_devices(
    timeout_seconds=MQTT_ALL_DEVICES_TIMEOUT
):
    """
    Wait until every device expected by the current combined
    ESP32/Wokwi experiment has published at least one observation.

    This makes Round 1 deterministic: the experiment does not
    begin while some real devices are still missing.
    """

    print(
        "[MQTT] Waiting for all expected devices: "
        f"{sorted(EXPECTED_MQTT_DEVICES)} "
        f"(timeout={timeout_seconds}s)..."
    )

    deadline = time.time() + timeout_seconds

    while time.time() < deadline:

        missing = EXPECTED_MQTT_DEVICES - received_mqtt_devices

        if not missing:
            all_expected_devices_event.set()

            print(
                "[MQTT] All expected device observations received."
            )
            return True

        all_expected_devices_event.wait(timeout=0.5)

    missing = EXPECTED_MQTT_DEVICES - received_mqtt_devices

    print("\n" + "=" * 80)
    print("[MQTT ERROR] Not all expected devices were received.")
    print(f"[MQTT ERROR] Missing devices: {sorted(missing)}")
    print("=" * 80)
    print("Received devices:")
    print(f"  {sorted(received_mqtt_devices)}")
    print("=" * 80)

    return False


def establish_mqtt_startup():
    """
    Establish the MQTT input layer before Round 1.

    The important research rule is:
        MQTT startup time is NOT counted as an experiment round.

    Round 1 starts only after MQTT is connected and the required
    real-device observations have arrived.
    """

    global mqtt_connected

    print("\n[MQTT] Starting MQTT input layer...")

    # Start the MQTT network loop before attempting connection so
    # asynchronous connection/message callbacks are serviced.
    mqtt_client.loop_start()

    connection_deadline = time.time() + MQTT_CONNECT_TIMEOUT

    while not mqtt_connected:

        try:
            mqtt_connected_event.clear()

            print(
                f"[MQTT] Connecting to {MQTT_BROKER}:{MQTT_PORT}..."
            )

            mqtt_client.connect(
                MQTT_BROKER,
                MQTT_PORT,
                60
            )

            remaining = max(
                0.1,
                connection_deadline - time.time()
            )

            if wait_for_mqtt_ready(remaining):
                break

        except Exception as exc:
            print(f"[MQTT] Connection attempt failed: {exc}")

        if time.time() >= connection_deadline:
            print(
                "[MQTT ERROR] Could not establish MQTT connection "
                f"within {MQTT_CONNECT_TIMEOUT} seconds."
            )
            return False

        print(
            f"[MQTT] Retrying in {MQTT_RETRY_DELAY} seconds..."
        )

        try:
            mqtt_client.disconnect()
        except Exception:
            pass

        time.sleep(MQTT_RETRY_DELAY)

    # A connected broker is not enough. We also need real device
    # observations before starting the first experiment round.
    if REQUIRE_MQTT_DATA:

        if not wait_for_first_mqtt_message(
            MQTT_FIRST_MESSAGE_TIMEOUT
        ):
            return False

        if not wait_for_all_expected_devices(
            MQTT_ALL_DEVICES_TIMEOUT
        ):
            return False

    print("\n" + "=" * 80)
    print("[MQTT] STARTUP COMPLETE")
    print("[MQTT] Broker connection: READY")
    print(
        "[MQTT] Real device observations: "
        f"{sorted(received_mqtt_devices)}"
    )
    print("[MQTT] Starting experiment at ROUND 1.")
    print("=" * 80)

    return True


# ============================================================
# START MQTT BEFORE ROUND 1
# ============================================================

try:

    mqtt_startup_ready = establish_mqtt_startup()

    if REQUIRE_MQTT_DATA and not mqtt_startup_ready:

        mqtt_client.loop_stop()

        raise SystemExit(
            "\n[STOPPED] MQTT startup was not completed. "
            "The hardware experiment was not started."
        )

except SystemExit:
    raise

except Exception as exc:

    try:
        mqtt_client.loop_stop()
    except Exception:
        pass

    raise SystemExit(
        f"\n[STOPPED] MQTT startup failed: {exc}"
    )


# ============================================================
# SIMULATION LOOP
# ============================================================

for round_number in range(



    1,



    TOTAL_ROUNDS + 1

):



    print("\n\n")



    print("=" * 80)



    print(

        f"                         ROUND {round_number}"

    )



    print("=" * 80)





    # ========================================================

    # PROCESS EACH DEVICE

    # ========================================================



    for device in devices:



        device_id = device.device_id



        print("\n")



        print("-" * 80)



        print(

            f"[DEVICE] Processing {device_id}"

        )



        print("-" * 80)





        # ====================================================

        # 1. UPDATE RESOURCE UTILIZATION

        # ====================================================



        device.update_resource_usage()



        print(

            "\n[1] Resource usage updated."

        )





        # ====================================================

        # ====================================================
        # 2. GENERATE / RECEIVE DEVICE DATA
        # ====================================================

        # Every device can now be driven by its ESP32/Wokwi
        # MQTT observation. If no MQTT observation has arrived
        # yet, the original simulator is used as a fallback.
        mqtt_data = mqtt_adapter.get_fresh_observation(
            device_id
        )

        if mqtt_data is not None:

            data = mqtt_data.copy()

            print(
                f"[2] {device_id} data received "
                f"through ESP32/MQTT."
            )

            observation_key = data.get("message_key") or data.get("_received_at_monotonic")
            if observation_key is None:
                print(f"[MQTT] {device_id}: no unique observation identity; skipping to avoid repeated scoring.")
                continue
            if last_processed_observation_keys.get(device_id) == observation_key:
                print(f"[MQTT] {device_id}: waiting for a new unique device reading.")
                mqtt_data = wait_for_new_observation(
                    device_id, last_processed_observation_keys.get(device_id), timeout_seconds=12
                )
                if mqtt_data is None:
                    print(f"[MQTT] {device_id}: no new reading within 12 seconds; skipping this round.")
                    continue
                data = mqtt_data.copy()
                observation_key = data.get("message_key") or data.get("_received_at_monotonic")
            last_processed_observation_keys[device_id] = observation_key

        elif REQUIRE_MQTT_DATA:

            print(
                f"[2] No MQTT observation for {device_id}; "
                "waiting for a real device message."
            )

            deadline = time.time() + 10

            while time.time() < deadline:
                mqtt_data = mqtt_adapter.get_fresh_observation(
                    device_id
                )

                if mqtt_data is not None:
                    break

                time.sleep(0.2)

            if mqtt_data is None:
                print(
                    f"[MQTT] No real observation for {device_id}; "
                    "skipping this device for this round."
                )
                continue

            data = mqtt_data.copy()

            print(
                f"[2] {device_id} data received "
                "through ESP32/MQTT."
            )

            observation_key = data.get("message_key") or data.get("_received_at_monotonic")
            if observation_key is None:
                print(f"[MQTT] {device_id}: no unique observation identity; skipping to avoid repeated scoring.")
                continue
            if last_processed_observation_keys.get(device_id) == observation_key:
                print(f"[MQTT] {device_id}: waiting for a new unique device reading.")
                mqtt_data = wait_for_new_observation(
                    device_id, last_processed_observation_keys.get(device_id), timeout_seconds=12
                )
                if mqtt_data is None:
                    print(f"[MQTT] {device_id}: no new reading within 12 seconds; skipping this round.")
                    continue
                data = mqtt_data.copy()
                observation_key = data.get("message_key") or data.get("_received_at_monotonic")
            last_processed_observation_keys[device_id] = observation_key

        else:

            data = device.generate_data()

            data["source"] = "SIMULATOR_FALLBACK"

            print(
                f"[2] No MQTT observation for {device_id}; "
                f"using simulator fallback."
            )


        # 3. ADD CURRENT CONTEXT

        # ====================================================



        current_context = (



            device.get_current_context()

        )



        data.update(



            current_context

        )



        print(

            "[3] Current context added."

        )





        # ====================================================

        # 4. INSPECT THE RECEIVED DEVICE READING
        #
        # This detector evaluates only the payload received from
        # MQTT plus gateway-known context. It does not inject attacks
        # and does not use a scheduled round as attack ground truth.
        # ====================================================

        device_attack_result = device_attack_detector.analyze(data)

        for indicator in device_attack_result["indicators"]:
            print(
                "[DEVICE EVIDENCE]",
                indicator["attack_type"],
                "| condition:", indicator["condition"],
                "| observed:", indicator["observed"],
                "| threshold:", indicator["threshold"],
                "| penalty:", indicator["penalty"],
                "| classification:", indicator["classification"],
            )

        if not device_attack_result["indicators"]:
            print("[DEVICE EVIDENCE] No configured anomaly condition triggered by this reading.")

        print(
            "[DEVICE EVIDENCE] Attack confirmed:",
            device_attack_result["confirmed_attack"],
            "| anomaly:", device_attack_result["anomaly_detected"],
        )

        # Use the verification result computed over the exact original MQTT
        # payload by MQTTDeviceAdapter. Never re-sign a received message at
        # the gateway and present that as device-origin authentication.
        raw_device_payload = data.get("raw_data", {})
        device_hmac_valid = raw_device_payload.get("device_hmac_valid")
        data["authentication_status"] = (device_hmac_valid is True)
        data["message_signature"] = raw_device_payload.get("message_signature")
        data["device_source_authenticated"] = (device_hmac_valid is True)
        data["integrity_status"] = raw_device_payload.get("integrity_status", "UNVERIFIED")
        print(
            "[6] Device-origin integrity:",
            data["integrity_status"],
            "| timestamp authenticated with payload:",
            device_hmac_valid is True,
        )

        # Feed measured anomaly penalties into behavior scoring.
        data["device_attack_indicators"] = device_attack_result["indicators"]


        # ====================================================

        # 8. BEHAVIOR ANALYSIS

        # ====================================================



        behavior_result = (



            behavior_analyzer.analyze(



                data

            )

        )



        behavior_score = (



            behavior_result[



                "behavior_score"

            ]

        )



        behavior_status = (



            behavior_result[



                "behavior_status"

            ]

        )



        print(



            "[8] Behavior analysis completed."

        )





        # ====================================================

        # 9. CONTEXT ANALYSIS

        # ====================================================



        context_result = (



            context_analyzer.analyze(



                data,



                device

            )

        )



        context_score = (



            context_result[



                "context_score"

            ]

        )



        context_status = (



            context_result[



                "context_status"

            ]

        )



        print(



            "[9] Context analysis completed."

        )





        # ====================================================

        # 10. DETERMINE ANOMALY

        # ====================================================



        behavior_score = min(
            float(behavior_score),
            float(device_attack_result["behavior_score"]),
        )
        behavior_result["behavior_score"] = behavior_score
        behavior_result["behavior_status"] = (
            "NORMAL" if behavior_score >= 0.80 else
            "SLIGHTLY_ABNORMAL" if behavior_score >= 0.60 else
            "SUSPICIOUS" if behavior_score >= 0.40 else
            "HIGHLY_ABNORMAL"
        )
        behavior_status = behavior_result["behavior_status"]

        anomaly = (
            behavior_score < 0.80
            or context_score < 0.80
            or device_attack_result["anomaly_detected"]
        )

        print("[10] Anomaly status:", anomaly)





        # ====================================================

        # 11. DETERMINE OBSERVATION SUCCESS
        # Success is based on observed scores, not scheduled attack labels.
        # ====================================================

        observation_success = (
            behavior_score >= 0.80
            and context_score >= 0.80
            and not device_attack_result["anomaly_detected"]
        )
        print("[11] Observation success:", observation_success)


        # ====================================================

        # 12. RECORD HISTORY

        #

        # IMPORTANT:

        #

        # No attack ground-truth label is passed into history.

        # ====================================================



        history_manager.record_observation(



            device_id=device_id,



            behavior_score=behavior_score,



            context_score=context_score,



            success=observation_success,



            anomaly=anomaly

        )



        print(



            "[12] History updated without attack ground truth."

        )





        # ====================================================

        # 13. HISTORY ANALYSIS

        # ====================================================



        history_result = (



            history_manager.analyze(



                device_id

            )

        )



        history_score = (



            history_result[



                "history_score"

            ]

        )



        print(



            "[13] History analysis completed."

        )





        # ====================================================

        # 14. RESOURCE CAPABILITY

        # ====================================================



        rcf = (



            resource_manager.calculate_rcf(



                device

            )

        )



        resource_level = (



            resource_manager.get_resource_level(



                rcf

            )

        )



        security_level = (



            resource_manager.get_security_level(



                rcf

            )

        )



        print(



            "[14] Resource capability calculated."

        )





        # ====================================================

        # 15. RESOURCE PRESSURE

        # ====================================================



        resource_pressure = (



            resource_manager.calculate_resource_pressure(



                device

            )

        )



        pressure_level = (



            resource_manager.get_pressure_level(



                resource_pressure

            )

        )



        print(



            "[15] Resource pressure calculated."

        )





        # ====================================================

        # 16. RESOURCE ANALYSIS

        # ====================================================



        resource_analysis = {



            "rcf":



                rcf,



            "resource_level":



                resource_level,



            "security_level":



                security_level,



            "resource_pressure":



                resource_pressure,



            "pressure_level":



                pressure_level

        }



        print(



            "[16] Resource analysis completed."

        )





        # ====================================================

        # 17. RISK ANALYSIS

        # ====================================================



        risk_result = (



            risk_engine.calculate_risk(



                behavior_score=



                    behavior_score,



                context_score=



                    context_score,



                device=



                    device,



                data=



                    data

            )

        )



        risk_score = (



            risk_result[



                "risk_score"

            ]

        )



        risk_status = (



            risk_result[



                "risk_status"

            ]

        )



        print(



            "[17] Risk analysis completed."

        )





        # ====================================================

        # 18. ADAPTIVE WEIGHT CALCULATION

        # ====================================================



        # ====================================================

        # FORENSIC SECURITY HISTORY

        # ====================================================



        forensic_incident = (



            history_result.get(



                "forensic_incident",



                False

            )

        )



        forensic_severity = (



            history_result.get(



                "last_severity",



                "UNKNOWN"

            )

        )





        # ====================================================

        # ADAPTIVE WEIGHT CALCULATION

        # ====================================================



        adaptive_weight_result = (



            adaptive_weight_engine.analyze(



                behavior_score=



                    behavior_score,



                context_score=



                    context_score,



                history_score=



                    history_score,



                risk_score=



                    risk_score,



                forensic_incident=



                    forensic_incident,



                forensic_severity=



                    forensic_severity

            )

        )



        print(



            "[18] Adaptive weights calculated."

        )





        # ====================================================

        # 19. ADAPTIVE TRUST CALCULATION

        # ====================================================



        trust_result = (



            trust_engine.analyze(



                behavior_score=



                    behavior_score,



                context_score=



                    context_score,



                history_score=



                    history_score,



                risk_score=



                    risk_score,



                adaptive_weights=



                    adaptive_weight_result

            )

        )



        trust_score = (



            trust_result[



                "trust_score"

            ]

        )



        trust_status = (



            trust_result[



                "trust_status"

            ]

        )



        print(



            "[19] Adaptive trust calculated."

        )





        # ====================================================

        # 20. ZERO-TRUST DECISION

        #

        # IMPORTANT:

        #

        # Attack ground truth is NOT supplied to the decision

        # engine.

        #

        # Detection must come from observed security evidence.

        # ====================================================





        decision_result = (



                decision_engine.analyze(



                    trust_score=



                        trust_score,



                    risk_score=



                        risk_score,



                    rcf=



                        rcf,



                    resource_pressure=



                        resource_pressure,



                    device_type=



                        device.device_type

                )

)



        decision = (



            decision_result[



                "decision"

            ]

        )



        decision_reason = (



            decision_result[



                "reason"

            ]

        )



        security_action = (



            decision_result[



                "security_action"

            ]

        )

        # Required device-origin integrity verification takes precedence over
        # adaptive trust. A failed/missing HMAC is not proof of attacker intent,
        # but the message must still be denied. Separately, explicitly confirmed
        # policy violations also override a trust-score ALLOW.
        if data.get("device_hmac_valid") is not True:
            decision = "DENY"
            decision_reason = "Device-origin message integrity is not verified"
            security_action = "REJECT_MESSAGE_AT_GATEWAY"
            decision_result["decision"] = decision
            decision_result["reason"] = decision_reason
            decision_result["security_action"] = security_action
            decision_result["requires_evidence"] = True
            print("[ZERO-TRUST OVERRIDE] Missing/failed device HMAC forces DENY.")
        elif device_attack_result["confirmed_attack"]:
            decision = "DENY"
            decision_reason = "Directly observed device policy violation"
            security_action = "BLOCK_REQUEST"
            decision_result["decision"] = decision
            decision_result["reason"] = decision_reason
            decision_result["security_action"] = security_action
            decision_result["requires_evidence"] = True
            print("[ZERO-TRUST OVERRIDE] Direct policy evidence forces DENY.")



        print(



            "[20] Zero-Trust decision calculated."

        )





        # ====================================================

        # 21. DETERMINE SECURITY DETECTION

        #

        # This is the current experimental detector.

        #

        # Ground truth is NOT used in this calculation.

        # ====================================================



        detected_attack = bool(
            device_attack_result["confirmed_attack"]
            or device_attack_result["anomaly_detected"]
            or decision == "DENY"
            or risk_score >= 0.60
            or behavior_score < 0.40
            or context_score < 0.40
        )

        print("[21] Attack/anomaly detected:", detected_attack)

        # Diagnostic trends only: live observations have no independent attack
        # labels, so do not label them NORMAL/ATTACK or derive precision/recall.
        visualizer.record(
            round_number=round_number,
            device=device,
            data=data,
            behavior_score=behavior_score,
            context_score=context_score,
            history_score=history_score,
            risk_score=risk_score,
            trust_score=trust_score,
            rcf=rcf,
            resource_pressure=resource_pressure,
            adaptive_weights=adaptive_weight_result,
            decision_result=decision_result,
            scenario_label="LIVE_UNLABELLED",
        )





        # ====================================================

        # 22. RECORD SECURITY METRICS

        #

        # ground_truth_attack is used ONLY here.

        # ====================================================



        # No independent attack ground-truth labels exist in live-only mode.
        # Do not manufacture TP/TN/FP/FN values from the detector output.



        print(



            "[22] Live observation processed; independent ground-truth metrics unavailable."

        )





        # ====================================================

        # 23. DISPLAY DEVICE INFORMATION

        # ====================================================



        print("\n")



        print(



            "[DEVICE INFORMATION]"

        )



        print(



            "Device ID           :",



            device_id

        )



        print(



            "Device Type         :",



            device.device_type

        )





        # ====================================================

        # 24. DISPLAY BEHAVIOR

        # ====================================================



        print("\n")



        print(



            "[BEHAVIOR ANALYSIS]"

        )



        print(



            "Behavior Score      :",



            behavior_score

        )



        print(



            "Behavior Status     :",



            behavior_status

        )





        # ====================================================

        # 25. DISPLAY CONTEXT

        # ====================================================



        print("\n")



        print(



            "[CONTEXT ANALYSIS]"

        )



        print(



            "Location Score      :",



            context_result[



                "location_score"

            ]

        )



        print(



            "Time Score          :",



            context_result[



                "time_score"

            ]

        )



        print(



            "Resource Score      :",



            context_result[



                "resource_score"

            ]

        )



        print(



            "Context Score       :",



            context_score

        )



        print(



            "Context Status      :",



            context_status

        )





        # ====================================================

        # 26. DISPLAY HISTORY

        # ====================================================



        print("\n")



        print(



            "[HISTORY ANALYSIS]"

        )



        print(



            "History Score       :",



            history_score

        )



        print(



            "History Status      :",



            history_result[



                "history_status"

            ]

        )



        print(



            "Success Rate        :",



            history_result[



                "success_rate"

            ]

        )



        print(



            "Failure Rate        :",



            history_result[



                "failure_rate"

            ]

        )



        print(



            "Anomaly Rate        :",



            history_result[



                "anomaly_rate"

            ]

        )



        print(



            "Forensic Incidents  :",



            history_result[



                "forensic_incidents"

            ]

        )



        print(



            "Confirmed Incidents :",



            history_result[



                "confirmed_incidents"

            ]

        )



        print(



            "Last Attack Type    :",



            history_result[



                "last_attack_type"

            ]

        )



        print(



            "Last Severity       :",



            history_result[



                "last_severity"

            ]

        )



        print(



            "Forensic Feedback   :",



            history_result[



                "forensic_incident"

            ]

        )





        # ====================================================

        # 27. DISPLAY ADAPTIVE WEIGHTS

        # ====================================================



        print("\n")



        print(



            "[ADAPTIVE WEIGHTS]"

        )



        print(



            "Behavior Weight     :",



            adaptive_weight_result[



                "behavior_weight"

            ]

        )



        print(



            "Context Weight      :",



            adaptive_weight_result[



                "context_weight"

            ]

        )



        print(



            "History Weight      :",



            adaptive_weight_result[



                "history_weight"

            ]

        )



        print(



            "Risk Weight         :",



            adaptive_weight_result[



                "risk_weight"

            ]

        )



        print(



            "Dominant Factor     :",



            adaptive_weight_result[



                "dominant_factor"

            ]

        )



        print(



            "Forensic Feedback   :",



            adaptive_weight_result[



                "forensic_feedback"

            ]

        )



        print(



            "Forensic Severity   :",



            adaptive_weight_result[



                "forensic_severity"

            ]

        )





        # ====================================================

        # 28. DISPLAY ADAPTIVE TRUST

        # ====================================================



        print("\n")



        print(



            "[ADAPTIVE TRUST]"

        )



        print(



            "Trust Score          :",



            trust_score

        )



        print(



            "Trust Status         :",



            trust_status

        )



        print(



            "Behavior Contribution:",



            trust_result[



                "behavior_contribution"

            ]

        )



        print(



            "Context Contribution :",



            trust_result[



                "context_contribution"

            ]

        )



        print(



            "History Contribution :",



            trust_result[



                "history_contribution"

            ]

        )



        print(



            "Risk Contribution    :",



            trust_result[



                "risk_contribution"

            ]

        )





        # ====================================================

        # 29. DISPLAY ZERO-TRUST DECISION

        # ====================================================



        print("\n")



        print(



            "[ZERO-TRUST DECISION]"

        )



        print(



            "Decision             :",



            decision

        )



        print(



            "Reason               :",



            decision_reason

        )



        print(



            "Security Action      :",



            security_action

        )



        print(



            "Attack Detected      :",



            detected_attack

        )



        print(



            "Requires Evidence    :",



            decision_result[



                "requires_evidence"

            ]

        )



        print(



            "Requires Isolation   :",



            decision_result[



                "requires_isolation"

            ]

        )





        # ====================================================

        # 30. DISPLAY RESOURCE INFORMATION

        # ====================================================



        print("\n")



        print(



            "[RESOURCE AWARENESS]"

        )



        print(



            "RCF                  :",



            rcf

        )



        print(



            "Resource Level       :",



            resource_level

        )



        print(



            "Security Level       :",



            security_level

        )



        print(



            "Resource Pressure    :",



            resource_pressure

        )



        print(



            "Pressure Level       :",



            pressure_level

        )





        # ====================================================

        # 31. DISPLAY CURRENT RESOURCE STATE

        # ====================================================



        current_resource_state = (



            device.get_current_resource_state()

        )



        print("\n")



        print(



            "[CURRENT RESOURCE STATE]"

        )



        print(



            "CPU Usage            :",



            current_resource_state[



                "cpu_usage"

            ]

        )



        print(



            "RAM Usage            :",



            current_resource_state[



                "ram_usage"

            ]

        )



        print(



            "Battery Level        :",



            current_resource_state[



                "battery_level"

            ]

        )



        print(



            "Bandwidth Usage      :",



            current_resource_state[



                "bandwidth_usage"

            ]

        )





        # ====================================================

        # 32. DISPLAY DEVICE-ORIGIN HMAC VERIFICATION

        # The MQTT adapter verifies the signature supplied by the device.
        # Do not generate a new gateway-side signature for a received payload.
        print("\n")
        print("[DEVICE-ORIGIN HMAC VERIFICATION]")
        print("Authentication Verified :", device_hmac_valid is True)
        print("Integrity Status        :", data.get("integrity_status", "UNVERIFIED"))
        print(
            "Device HMAC Signature  :",
            raw_device_payload.get("message_signature", "NOT PROVIDED"),
        )


        # 33. DISPLAY BASIC TRUST MANAGER

        # ====================================================



        basic_trust_score = (



            trust_manager.get_trust_score(



                device_id

            )

        )



        basic_trust_status = (



            trust_manager.get_status(



                device_id

            )

        )



        print("\n")



        print(



            "[LEGACY TRUST MANAGER]"

        )



        print(



            "Basic Trust Score    :",



            round(



                basic_trust_score,



                3

            )

        )



        print(



            "Basic Trust Status   :",



            basic_trust_status

        )





        # ====================================================

        # 34. ATTACH ANALYSIS TO MESSAGE

        # ====================================================



        data[



            "adaptive_trust"



        ] = {



            "trust_score":



                trust_result[



                    "trust_score"

                ],



            "trust_status":



                trust_result[



                    "trust_status"

                ],



            "behavior_contribution":



                trust_result[



                    "behavior_contribution"

                ],



            "context_contribution":



                trust_result[



                    "context_contribution"

                ],



            "history_contribution":



                trust_result[



                    "history_contribution"

                ],



            "risk_contribution":



                trust_result[



                    "risk_contribution"

                ]

        }





        data[



            "risk_analysis"



        ] = risk_result





        data[



            "decision_analysis"



        ] = decision_result





        data[



            "resource_analysis"



        ] = resource_analysis





        # ====================================================

        # 35. SEND DATA TO RASPBERRY PI

        # ====================================================



        print("\n")



        print(



            "[EDGE] Sending device data to Raspberry Pi..."

        )



        raspberry_pi.receive_data(



            data

        )





        # ====================================================

        # 36. RASPBERRY PI SENDS DATA TO GATEWAY

        # ====================================================



        print(



            "[EDGE] Raspberry Pi forwarding data to Gateway..."

        )



        raspberry_pi.send_to_gateway(



            gateway

        )





        # ====================================================

        # DEVICE PROCESSING COMPLETE

        # ====================================================



        print("\n")



        print(



            f"[DEVICE COMPLETE] {device_id}"

        )



        print(



            "-" * 80

        )





    # ========================================================

    # END OF ROUND

    # ========================================================



    print("\n")



    print(



        f"[ROUND {round_number}] Completed."

    )



    print("=" * 80)





    # ========================================================

    # WAIT BEFORE NEXT ROUND

    # ========================================================



    print("[ROUND DELAY] Pausing 10 seconds so this round's values remain visible...")

    time.sleep(10)





# ============================================================

# SAVE LIVE DIAGNOSTIC PLOTS
# ============================================================

print("\n[PLOTS] Saving round-by-round diagnostic plots (live data is unlabelled)...")
visualizer.save_and_plot()


# CONTROLLED RECOVERY EXPERIMENT

# ============================================================



print("\n\n")



print("=" * 80)



print(



    "                  DEVICE RECOVERY EXPERIMENT"

)



print("=" * 80)





# ============================================================

# CHECK ISOLATED DEVICES

# ============================================================



isolated_devices = (



    gateway.get_isolated_devices()

)



print(



    "\nCurrently isolated devices:",



    isolated_devices

)





# ============================================================

# RECOVERY TARGET

# ============================================================



RECOVERY_DEVICE = isolated_devices[0] if isolated_devices else None





if RECOVERY_DEVICE is not None and gateway.is_device_isolated(



    RECOVERY_DEVICE

):



    print("\n")



    print(



        f"[RECOVERY] Recovery target: {RECOVERY_DEVICE}"

    )



    print(



        "[RECOVERY] Device is currently isolated."

    )



    print(



        "[RECOVERY] Beginning controlled remediation."

    )





    # --------------------------------------------------------

    # POST-REMEDIATION SECURITY MEASUREMENTS

    #

    # These are synthetic demonstration inputs for the recovery

    # manager, NOT live post-remediation measurements and NOT

    # attack ground truth. Replace them with measured values before

    # using recovery outcomes as experimental results.

    # --------------------------------------------------------



    recovery_authentication = True



    recovery_behavior_score = 0.92



    recovery_context_score = 0.95



    recovery_risk_score = 0.12



    recovery_trust_score = 0.86





    # --------------------------------------------------------

    # Retrieve previous forensic result

    # --------------------------------------------------------



    previous_security_state = (



        gateway.get_device_security_state(



            RECOVERY_DEVICE

        )

    )



    previous_forensic_result = (



        previous_security_state.get(



            "forensic_analysis",



            {}

        )

    )





    # --------------------------------------------------------

    # Perform recovery

    # --------------------------------------------------------



    recovery_result = (



        gateway.recover_device(



            device_id=



                RECOVERY_DEVICE,



            authentication_result=



                recovery_authentication,



            behavior_score=



                recovery_behavior_score,



            context_score=



                recovery_context_score,



            risk_score=



                recovery_risk_score,



            trust_score=



                recovery_trust_score,



            forensic_result=



                previous_forensic_result

        )

    )





    # --------------------------------------------------------

    # DISPLAY RECOVERY RESULT

    # --------------------------------------------------------



    print("\n")



    print("=" * 80)



    print(



        "                    RECOVERY RESULT"

    )



    print("=" * 80)



    print(



        "Device              :",



        recovery_result.get(



            "device_id",



            RECOVERY_DEVICE

        )

    )



    print(



        "Recovery Status     :",



        recovery_result.get(



            "recovery_status",



            "UNKNOWN"

        )

    )



    print(



        "Authentication      :",



        recovery_result.get(



            "authentication",



            "UNKNOWN"

        )

    )



    print(



        "Behavior Score      :",



        recovery_result.get(



            "behavior_score",



            "UNKNOWN"

        )

    )



    print(



        "Context Score       :",



        recovery_result.get(



            "context_score",



            "UNKNOWN"

        )

    )



    print(



        "Risk Score          :",



        recovery_result.get(



            "risk_score",



            "UNKNOWN"

        )

    )



    print(



        "Trust Score         :",



        recovery_result.get(



            "trust_score",



            "UNKNOWN"

        )

    )



    print("=" * 80)





else:



    print(



        f"\n[RECOVERY] {RECOVERY_DEVICE} is not isolated."

    )



    print(



        "[RECOVERY] Recovery experiment skipped."

    )





# ============================================================

# SECURITY METRICS

# ============================================================



print("\n[METRICS] Detection-quality metrics (precision/recall/FPR/FNR) are not computed in live-only mode because no independent attack ground-truth labels are supplied.")





# ============================================================

# FINAL SIMULATION RESULTS

# ============================================================



print("\n\n")



print("=" * 80)



print(



    "                    FINAL SIMULATION RESULTS"

)



print("=" * 80)





# ============================================================

# FINAL DEVICE STATUS

# ============================================================



for device in devices:



    device_id = device.device_id



    print("\n")



    print("-" * 80)



    print(



        f"DEVICE: {device_id}"

    )



    print("-" * 80)





    # ========================================================

    # BASIC TRUST

    # ========================================================



    final_basic_trust = (



        trust_manager.get_trust_score(



            device_id

        )

    )



    final_basic_status = (



        trust_manager.get_status(



            device_id

        )

    )



    print(



        "Basic Trust Score       :",



        round(



            final_basic_trust,



            3

        )

    )



    print(



        "Basic Trust Status      :",



        final_basic_status

    )





    # ========================================================

    # HISTORY

    # ========================================================



    final_history = (



        history_manager.analyze(



            device_id

        )

    )



    print(



        "Final History Score     :",



        final_history[



            "history_score"

        ]

    )



    print(



        "Final Anomaly Rate      :",



        final_history[



            "anomaly_rate"

        ]

    )



    print(



        "Forensic Incidents      :",



        final_history[



            "forensic_incidents"

        ]

    )



    print(



        "Confirmed Incidents     :",



        final_history[



            "confirmed_incidents"

        ]

    )



    print(



        "Last Attack Type        :",



        final_history[



            "last_attack_type"

        ]

    )



    print(



        "Last Severity           :",



        final_history[



            "last_severity"

        ]

    )



    print(



        "Forensic Feedback       :",



        final_history[



            "forensic_incident"

        ]

    )





    # ========================================================

    # ISOLATION

    # ========================================================



    isolated = (



        gateway.is_device_isolated(



            device_id

        )

    )



    print(



        "Device Isolated         :",



        isolated

    )





    # ========================================================

    # FINAL GATEWAY SECURITY STATE

    # ========================================================



    security_state = (



        gateway.get_device_security_state(



            device_id

        )

    )



    print(



        "Final Gateway Decision  :",



        security_state.get(



            "decision",



            "UNKNOWN"

        )

    )



    print(



        "Final Security Action   :",



        security_state.get(



            "security_action",



            "UNKNOWN"

        )

    )



    print(



        "Recovery Status         :",



        security_state.get(



            "recovery_status",



            "NOT_RECOVERED"

        )

    )





# ============================================================

# ISOLATED DEVICE SUMMARY

# ============================================================



print("\n")



print("=" * 80)



print(



    "                    ISOLATED DEVICES"

)



print("=" * 80)





isolated_devices = (



    gateway.get_isolated_devices()

)





if len(isolated_devices) == 0:



    print(



        "No devices were isolated."

    )



else:



    for device_id in isolated_devices:



        print(



            f"🚨 {device_id}"

        )





# ============================================================

# ATTACK HISTORY

# ============================================================



print("\n")



print("=" * 80)



print(



    "                       ATTACK HISTORY"

)



print("=" * 80)





attack_history = device_attack_detector.get_incidents()





if len(attack_history) == 0:



    print(



        "No device attack indicators were recorded."

    )



else:



    for attack in attack_history:



        print(



            "\nDevice      :",



            attack.get(



                "device_id"

            )

        )



        print(



            "Attack Type :",



            attack.get(



                "attack_type"

            )

        )



        print(



            "Description :",



            attack.get(



                "description"

            )

        )





# ============================================================

# RECOVERY HISTORY

# ============================================================



print("\n")



print("=" * 80)



print(



    "                      RECOVERY HISTORY"

)



print("=" * 80)





for device in devices:



    device_id = device.device_id



    recovery_history = (



        gateway.get_recovery_history(



            device_id

        )

    )



    if len(recovery_history) > 0:



        print(



            f"\nDevice: {device_id}"

        )



        for event in recovery_history:



            print(



                "  Status:",



                event.get(



                    "recovery_status",



                    "UNKNOWN"

                )

            )



            print(



                "  Timestamp:",



                event.get(



                    "timestamp",



                    "UNKNOWN"

                )

            )





# ============================================================

# SIMULATION SUMMARY

# ============================================================



print("\n")



print("=" * 80)



print(



    "                    SIMULATION SUMMARY"

)



print("=" * 80)





print(



    "\nThe simulation evaluated:"

)



print(



    "1. Device Behaviour"

)



print(



    "2. Device Context"

)



print(



    "3. Historical Trust"

)



print(



    "4. Risk Assessment"

)



print(



    "5. Adaptive Trust Weights"

)



print(



    "6. Resource Capability"

)



print(



    "7. Resource Pressure"

)



print(



    "8. Device-origin HMAC-SHA256 verification over raw MQTT payload"

)



print(



    "9. Device-specific telemetry anomaly checks"

)



print(



    "10. Device-origin HMAC and signed timestamp verification enabled in firmware"

)



print(



    "11. Zero-Trust Decision Making"

)



print(



    "12. Forensic Evidence Collection"

)



print(



    "13. Forensic Analysis"

)



print(



    "14. Device Isolation"

)



print(



    "15. Device Re-authentication"

)



print(



    "16. Security Re-evaluation"

)



print(



    "17. Device Recovery"

)



print(



    "18. Forensic Feedback into Security History"

)



print(



    "19. Forensic-Aware Adaptive Weighting"

)



print(



    "20. Security Evaluation Metrics"

)





print("\n")



print("=" * 80)



# ============================================================
# STOP MQTT CLIENT
# ============================================================

try:
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    print("[MQTT] MQTT client stopped.")
except Exception:
    pass


print(



    "              SIMULATION COMPLETED"

)



print("=" * 80)