import time

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
# INITIALIZE RASPBERRY PI
# ============================================================

raspberry_pi = RaspberryPi()


# ============================================================
# INITIALIZE GATEWAY
# ============================================================

gateway = Gateway(
    trust_manager=trust_manager,
    evidence_collector=evidence_collector,
    crypto=crypto
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

# Device compromise starts at this round
ATTACK_ROUND = 6

# Device that will be compromised
ATTACKED_DEVICE = "MOTION_001"

# ------------------------------------------------------------
# Controlled message-tampering scenario
#
# We deliberately tamper with a message from CAMERA_001
# during this round.
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
        # 2. GENERATE DEVICE DATA
        # ====================================================

        data = device.generate_data()

        print(
            "[2] Device data generated."
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
        # 4. CHECK DEVICE COMPROMISE
        # ====================================================

        compromised = (
            attack_simulator.is_compromised(
                device_id
            )
        )

        print(
            "[4] Device compromise status:",
            compromised
        )


        # ====================================================
        # 5. GENERATE MALICIOUS BEHAVIOR
        #
        # IMPORTANT:
        #
        # If device is compromised, malicious behavior is
        # generated BEFORE HMAC.
        #
        # Therefore the compromised device can still generate
        # a valid HMAC.
        #
        # This demonstrates:
        #
        # Authentication != Trust
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
        #
        # HMAC is generated BEFORE any controlled tampering.
        # ====================================================

        crypto_result = (
            crypto.authenticate_message(
                device_id,
                data
            )
        )

        data["authentication_status"] = (
            crypto_result[
                "authenticated"
            ]
        )

        data["message_signature"] = (
            crypto_result[
                "signature"
            ]
        )

        print(
            "[6] HMAC authentication generated."
        )


        # ====================================================
        # 7. CONTROLLED MESSAGE TAMPERING
        #
        # IMPORTANT:
        #
        # HMAC has already been generated.
        #
        # Therefore modifying the message now should cause
        # Gateway HMAC verification to fail.
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
        # ====================================================

        history_manager.record_observation(

            device_id=device_id,

            behavior_score=behavior_score,

            context_score=context_score,

            success=observation_success,

            anomaly=anomaly,

            compromised=compromised

        )

        print(
            "[12] Historical observation recorded."
        )


        # ====================================================
        # 13. ANALYZE HISTORY
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

        history_status = (
            history_result[
                "history_status"
            ]
        )

        previous_compromise = (
            history_result[
                "previous_compromise"
            ]
        )

        print(
            "[13] History analysis completed."
        )


        # ====================================================
        # 14. CALCULATE RESOURCE CAPABILITY FACTOR
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
            "[14] Resource Capability Factor calculated."
        )


        # ====================================================
        # 15. CALCULATE RESOURCE PRESSURE
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
        # 16. RESOURCE ANALYSIS OBJECT
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

                previous_compromise=
                    previous_compromise

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
                    device.device_type,

                compromised=
                    compromised

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

        print(
            "[20] Zero-Trust decision generated."
        )


        # ====================================================
        # 21. DISPLAY BEHAVIOR INFORMATION
        # ====================================================

        print("\n")
        print("[BEHAVIOR ANALYSIS]")

        print(
            "Behavior Score       :",
            behavior_score
        )

        print(
            "Behavior Status      :",
            behavior_status
        )


        # ====================================================
        # 22. DISPLAY CONTEXT INFORMATION
        # ====================================================

        print("\n")
        print("[CONTEXT ANALYSIS]")

        print(
            "Location Score       :",
            context_result[
                "location_score"
            ]
        )

        print(
            "Time Score           :",
            context_result[
                "time_score"
            ]
        )

        print(
            "Resource Score       :",
            context_result[
                "resource_score"
            ]
        )

        print(
            "Context Score        :",
            context_score
        )

        print(
            "Context Status       :",
            context_status
        )


        # ====================================================
        # 23. DISPLAY HISTORY INFORMATION
        # ====================================================

        print("\n")
        print("[HISTORY ANALYSIS]")

        print(
            "History Score        :",
            history_score
        )

        print(
            "History Status       :",
            history_status
        )

        print(
            "Success Rate         :",
            history_result[
                "success_rate"
            ]
        )

        print(
            "Failure Rate         :",
            history_result[
                "failure_rate"
            ]
        )

        print(
            "Anomaly Rate         :",
            history_result[
                "anomaly_rate"
            ]
        )

        print(
            "Previous Compromise  :",
            previous_compromise
        )


        # ====================================================
        # 24. DISPLAY RISK INFORMATION
        # ====================================================

        print("\n")
        print("[RISK ANALYSIS]")

        print(
            "Probability of Compromise:",
            risk_result[
                "probability_of_compromise"
            ]
        )

        print(
            "Impact               :",
            risk_result[
                "impact"
            ]
        )

        print(
            "Vulnerability       :",
            risk_result[
                "vulnerability"
            ]
        )

        print(
            "Resource Sensitivity:",
            risk_result[
                "resource_sensitivity"
            ]
        )

        print(
            "Exposure             :",
            risk_result[
                "exposure"
            ]
        )

        print(
            "Risk Score           :",
            risk_score
        )

        print(
            "Risk Status          :",
            risk_status
        )


        # ====================================================
        # 25. DISPLAY ADAPTIVE WEIGHTS
        # ====================================================

        print("\n")
        print("[ADAPTIVE WEIGHTS]")

        print(
            "Behavior Weight      :",
            adaptive_weight_result[
                "behavior_weight"
            ]
        )

        print(
            "Context Weight       :",
            adaptive_weight_result[
                "context_weight"
            ]
        )

        print(
            "History Weight       :",
            adaptive_weight_result[
                "history_weight"
            ]
        )

        print(
            "Risk Weight          :",
            adaptive_weight_result[
                "risk_weight"
            ]
        )

        print(
            "Dominant Factor      :",
            adaptive_weight_result[
                "dominant_factor"
            ]
        )


        # ====================================================
        # 26. DISPLAY ADAPTIVE TRUST
        # ====================================================

        print("\n")
        print("[ADAPTIVE TRUST]")

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
        # 27. DISPLAY ZERO-TRUST DECISION
        # ====================================================

        print("\n")
        print("[ZERO-TRUST DECISION]")

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
            "Requires Evidence   :",
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
        # 28. DISPLAY RESOURCE INFORMATION
        # ====================================================

        print("\n")
        print("[RESOURCE AWARENESS]")

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
        # 29. DISPLAY CURRENT RESOURCE STATE
        # ====================================================

        current_resource_state = (
            device.get_current_resource_state()
        )

        print("\n")
        print("[CURRENT RESOURCE STATE]")

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
        # 30. DISPLAY LIGHTWEIGHT CRYPTOGRAPHY
        # ====================================================

        print("\n")
        print("[LIGHTWEIGHT CRYPTOGRAPHY]")

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
        # 31. DISPLAY BASIC TRUST MANAGER
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
        print("[LEGACY TRUST MANAGER]")

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
        # 32. ATTACH ANALYSIS TO MESSAGE
        #
        # IMPORTANT:
        #
        # These fields are generated AFTER HMAC.
        #
        # gateway.py removes these fields before HMAC
        # verification because they were not part of the
        # original signed message.
        # ====================================================

        data["adaptive_trust"] = {

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


        data["risk_analysis"] = (
            risk_result
        )


        data["decision_analysis"] = (
            decision_result
        )


        data["resource_analysis"] = (
            resource_analysis
        )


        # ====================================================
        # 33. SEND DATA TO RASPBERRY PI
        # ====================================================

        print("\n")

        print(
            "[EDGE] Sending device data to Raspberry Pi..."
        )

        raspberry_pi.receive_data(
            data
        )


        # ====================================================
        # 34. RASPBERRY PI SENDS DATA TO GATEWAY
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

        print("-" * 80)


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
        "Previous Compromise     :",
        final_history[
            "previous_compromise"
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
    "13. Device Isolation"
)


print("\n")

print("=" * 80)

print(
    "              SIMULATION COMPLETED"
)

print("=" * 80)