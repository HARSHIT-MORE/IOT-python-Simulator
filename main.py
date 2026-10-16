import time
import json
import threading
import paho.mqtt.client as mqtt

from iot.mqtt_adapter import MQTTDeviceAdapter
from experiments.attack_visualizer import ExperimentVisualizer





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



from security.attack_simulator import AttackSimulator



from security.evidence_collector import EvidenceCollector



from security.crypto import LightweightCrypto





# ============================================================

# EXPERIMENT IMPORTS

# ============================================================



from experiments.metrics import SecurityMetrics





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



attack_simulator = AttackSimulator()



evidence_collector = EvidenceCollector()



crypto = LightweightCrypto()





# ============================================================

# INITIALIZE METRICS

# ============================================================



metrics = SecurityMetrics()

experiment_visualizer = ExperimentVisualizer(
    output_dir="experiments/results"
)





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

# SIMULATION CONFIGURATION

# ============================================================



TOTAL_ROUNDS = 15





# ------------------------------------------------------------

# Device compromise starts at this round

# ------------------------------------------------------------



ATTACK_ROUND = 6





# ------------------------------------------------------------

# Device that will be compromised

# ------------------------------------------------------------



ATTACKED_DEVICE = "MOTION_001"





# ------------------------------------------------------------

# Controlled message tampering

# ------------------------------------------------------------



TAMPERING_ROUND = 10



TAMPERING_DEVICE = "CAMERA_001"





# ============================================================

# START SIMULATION

# ============================================================



print("\n")



print("=" * 80)



print(

    "       ADAPTIVE RESOURCE-AWARE ZERO-TRUST IoT SIMULATION"

)



print("=" * 80)



print(

    f"\nTotal Simulation Rounds : {TOTAL_ROUNDS}"

)



print(

    f"Compromise Starts       : Round {ATTACK_ROUND}"

)



print(

    f"Compromised Device      : {ATTACKED_DEVICE}"

)



print(

    f"Tampering Round         : {TAMPERING_ROUND}"

)



print(

    f"Tampered Device         : {TAMPERING_DEVICE}"

)



print("=" * 80)





# ============================================================
# MQTT CONFIGURATION
# ============================================================

MQTT_BROKER = "test.mosquitto.org"
MQTT_PORT = 1883
# Subscribe to every ESP32/Wokwi device topic, not only temperature.
MQTT_TOPIC = "harshit/iot/#"
EXPECTED_MQTT_DEVICES = {
    "TEMP_001", "MOTION_001", "CLOCK_001", "CAMERA_001"
}
MQTT_STARTUP_TIMEOUT = 60

mqtt_adapter = MQTTDeviceAdapter()
received_mqtt_devices = set()
all_expected_mqtt_devices_received = threading.Event()


# ============================================================
# MQTT CALLBACKS
# ============================================================

def mqtt_on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("\n[MQTT] Connected to MQTT broker")
        result, mid = client.subscribe(MQTT_TOPIC)
        print(f"[MQTT] Subscribed to: {MQTT_TOPIC} (result={result})")
    else:
        print(f"[MQTT] Connection failed: {reason_code}")


def mqtt_on_message(client, userdata, msg):
    # A retained message may be an old value left on the public broker
    # from a previous Wokwi run. It is NOT proof that Wokwi is running now.
    if msg.retain:
        print(f"[MQTT] Ignoring retained/stored message on {msg.topic}; waiting for live Wokwi publish.")
        return

    topic_device_id = msg.topic.rsplit("/", 1)[-1]
    if topic_device_id not in EXPECTED_MQTT_DEVICES:
        print(f"[MQTT] Ignoring unexpected topic: {msg.topic}")
        return

    payload = msg.payload.decode("utf-8", errors="replace")
    # MQTTDeviceAdapter.process_message requires both topic and payload.
    observation = mqtt_adapter.process_message(msg.topic, payload)
    if observation is None:
        print(f"[MQTT] Could not parse message on {msg.topic}")
        return

    device_id = observation.get("device_id", "UNKNOWN")
    if device_id != topic_device_id:
        print(f"[MQTT] Rejecting topic/payload mismatch: topic says {topic_device_id}, payload says {device_id}")
        return
    if device_id not in EXPECTED_MQTT_DEVICES:
        print(f"[MQTT] Ignoring unknown device ID: {device_id}")
        return

    received_mqtt_devices.add(device_id)
    print(f"\n[MQTT] RECEIVED topic={msg.topic} device={device_id} "
          f"type={observation.get('device_type')} source=MQTT")

    if device_id == "TEMP_001":
        print(f"[MQTT] temperature={observation.get('temperature')} C, "
              f"humidity={observation.get('humidity')} %")
    elif device_id == "MOTION_001":
        print(f"[MQTT] motion_detected={observation.get('motion_detected')}")
    elif device_id == "CLOCK_001":
        print(f"[MQTT] clock={observation.get('hour')}:"
              f"{observation.get('minute')}:"
              f"{observation.get('second')}")
    elif device_id == "CAMERA_001":
        print(f"[MQTT] object_detected={observation.get('object_detected')}, "
              f"fps={observation.get('fps')}, "
              f"image_size_bytes={observation.get('image_size_bytes')}")

    missing = EXPECTED_MQTT_DEVICES - received_mqtt_devices
    print(f"[MQTT] Device startup status: received={len(received_mqtt_devices)}/"
          f"{len(EXPECTED_MQTT_DEVICES)}; missing={sorted(missing)}")
    if not missing:
        all_expected_mqtt_devices_received.set()


# ============================================================
# MQTT CLIENT AND STRICT STARTUP CHECK
# ============================================================

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqtt_client.on_connect = mqtt_on_connect
mqtt_client.on_message = mqtt_on_message

try:
    print(f"[MQTT] Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
    mqtt_client.loop_start()
except Exception as exc:
    raise SystemExit(f"[MQTT] Connection could not be started: {exc}")

print(f"[MQTT] Waiting up to {MQTT_STARTUP_TIMEOUT}s for LIVE (non-retained) messages from all four Wokwi devices...")
if not all_expected_mqtt_devices_received.wait(MQTT_STARTUP_TIMEOUT):
    missing = EXPECTED_MQTT_DEVICES - received_mqtt_devices
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    raise SystemExit(
        "[MQTT] STARTUP FAILED: no simulation was run because readings were "
        f"not received from every expected device. Missing: {sorted(missing)}. "
        "Retained messages are ignored. Start the Wokwi ESP32 simulation and check that it is actively publishing to harshit/iot/<DEVICE_ID>. "
        "and the broker/port are correct."
    )

print("\n[MQTT] STARTUP COMPLETE — readings received for all devices:")
print(f"[MQTT] {sorted(received_mqtt_devices & EXPECTED_MQTT_DEVICES)}")


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

    # DEVICE COMPROMISE

    # ========================================================



    if round_number == ATTACK_ROUND:



        print("\n")



        print("*" * 80)



        print(

            f"[ATTACK] Compromising device: "

            f"{ATTACKED_DEVICE}"

        )



        attack_simulator.compromise_device(



            ATTACKED_DEVICE

        )



        print("*" * 80)





    # ========================================================

    # MESSAGE TAMPERING EVENT

    # ========================================================



    if round_number == TAMPERING_ROUND:



        print("\n")



        print("*" * 80)



        print(

            f"[ATTACK] Message tampering scheduled for: "

            f"{TAMPERING_DEVICE}"

        )



        print("*" * 80)





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
        # 2. RECEIVE DEVICE DATA FROM MQTT
        # ====================================================

        # mqtt_data = mqtt_adapter.get_latest_observation(device_id)

        mqtt_data = mqtt_adapter.get_fresh_observation(
            device_id,
            max_age_seconds=15
        )

        if mqtt_data is not None:
            data = mqtt_data.copy()

            print(
                f"[2] {device_id} received fresh MQTT data. "
                f"Age={data['message_age_seconds']}s"
            )

        if mqtt_data is not None and device_id in EXPECTED_MQTT_DEVICES:
            data = mqtt_data.copy()
            data["source"] = "MQTT"
            print(f"[2] {device_id} observation source: MQTT")
            print(f"[2] MQTT payload fields: "
                  f"{ {k: v for k, v in data.items() if k != 'raw_data'} }")
        else:
            # Strict mode: do not quietly replace missing live readings
            # with synthetic readings in a hardware-in-the-loop experiment.
            raise RuntimeError(
                f"[MQTT] No MQTT observation available for {device_id}; "
                "refusing to silently use simulated data."
            )


        # ====================================================

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

        # 4. CHECK ATTACK GROUND TRUTH

        #

        # IMPORTANT:

        #

        # This is used ONLY for generating the controlled

        # attack scenario and later evaluating detection.

        #

        # It is NOT passed to HistoryManager.

        # It is NOT used by TrustEngine.

        # It is NOT used by DecisionEngine.

        # ====================================================



        compromised = (



            attack_simulator.is_compromised(



                device_id

            )

        )



        print(



            "[4] Attack ground truth:",



            compromised

        )





        # ====================================================

        # 5. GENERATE MALICIOUS BEHAVIOR

        # ====================================================



        if compromised:



            data = (



                attack_simulator.generate_malicious_data(



                    data

                )

            )



            print(



                "[5] Malicious behavior generated."

            )



        else:



            print(



                "[5] Normal device behavior."

            )





        # ====================================================

        # 6. GENERATE HMAC

        # ====================================================



        crypto_result = (



            crypto.authenticate_message(



                device_id,



                data

            )

        )



        data[



            "authentication_status"



        ] = (



            crypto_result[



                "authenticated"

            ]

        )



        data[



            "message_signature"



        ] = (



            crypto_result[



                "signature"

            ]

        )



        print(



            "[6] HMAC authentication generated."

        )





        # ====================================================

        # 7. CONTROLLED MESSAGE TAMPERING

        # ====================================================



        tampering_attack = (



            round_number == TAMPERING_ROUND



            and



            device_id == TAMPERING_DEVICE

        )



        if tampering_attack:



            data = (



                attack_simulator.tamper_message(



                    data

                )

            )



            print(



                "[7] Message was tampered AFTER HMAC generation."

            )



        else:



            print(



                "[7] No message tampering."

            )





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



        anomaly = (



            behavior_score < 0.80



            or



            context_score < 0.80



            or



            data.get(



                "malicious_activity",



                False

            )

        )



        print(



            "[10] Anomaly status:",



            anomaly

        )





        # ====================================================

        # 11. DETERMINE OBSERVATION SUCCESS

        # ====================================================



        observation_success = (



            behavior_score >= 0.80



            and



            context_score >= 0.80



            and



            not data.get(



                "malicious_activity",



                False

            )



            and



            not tampering_attack

        )



        print(



            "[11] Observation success:",



            observation_success

        )





        # ====================================================

        # 12. RECORD HISTORY

        #

        # IMPORTANT:

        #

        # compromised is intentionally NOT passed here.

        #

        # This prevents attack ground truth from influencing

        # historical trust.

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



        # Round-level diagnostics. Scenario labels are stored for plotting only;
        # they are never passed to the trust or decision engines.
        if tampering_attack:
            scenario_label = "MESSAGE_TAMPERING"
        elif compromised:
            scenario_label = "DEVICE_COMPROMISE"
        else:
            scenario_label = "NORMAL"

        experiment_visualizer.record(
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
            scenario_label=scenario_label,
        )

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



        detected_attack = (



            decision in [



                "DENY",



                "RESTRICT"

            ]



            or



            risk_score >= 0.60



            or



            behavior_score < 0.40



            or



            context_score < 0.40

        )



        print(



            "[21] Attack detected:",



            detected_attack

        )





        # ====================================================

        # 22. RECORD SECURITY METRICS

        #

        # ground_truth_attack is used ONLY here.

        # ====================================================



        metrics.add_record(



            device_id=device_id,



            round_number=round_number,



            ground_truth_attack=compromised,



            detected_attack=detected_attack,



            decision=decision,



            trust_score=trust_score,



            risk_score=risk_score,



            behavior_score=behavior_score,



            context_score=context_score

        )



        print(



            "[22] Security evaluation record stored."

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

        # 32. DISPLAY LIGHTWEIGHT CRYPTOGRAPHY

        # ====================================================



        print("\n")



        print(



            "[LIGHTWEIGHT CRYPTOGRAPHY]"

        )



        print(



            "Authentication       :",



            crypto_result[



                "authenticated"

            ]

        )



        print(



            "HMAC Generated       :",



            crypto_result[



                "signature"

            ]

        )





        # ====================================================

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



    if round_number < TOTAL_ROUNDS:



        time.sleep(2)





# ============================================================

# Save round-level CSV and plots after the simulation rounds.
experiment_visualizer.save_and_plot()


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



RECOVERY_DEVICE = ATTACKED_DEVICE





if gateway.is_device_isolated(



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

    # These values represent measurements obtained after

    # remediation in the current simulation.

    #

    # They are NOT attack ground truth.

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



metrics.display_metrics()





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





attack_history = (



    attack_simulator.get_attack_history()

)





if len(attack_history) == 0:



    print(



        "No attacks were recorded."

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



    "8. Lightweight HMAC Authentication"

)



print(



    "9. Compromised Device Detection"

)



print(



    "10. Message Tampering Detection"

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