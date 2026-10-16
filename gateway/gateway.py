import time

from security.forensic_analyzer import ForensicAnalyzer
from security.recovery_manager import RecoveryManager


class Gateway:

    def __init__(
        self,
        trust_manager,
        evidence_collector,
        crypto,
        history_manager
    ):

        # ========================================================
        # EXISTING COMPONENTS
        # ========================================================

        self.trust_manager = trust_manager
        self.evidence_collector = evidence_collector
        self.crypto = crypto
        self.history_manager = history_manager

        # ========================================================
        # FORENSIC MODULE
        # ========================================================

        self.forensic_analyzer = ForensicAnalyzer()

        # ========================================================
        # RECOVERY MODULE
        # ========================================================

        self.recovery_manager = RecoveryManager()

        # ========================================================
        # DEVICES THAT HAVE BEEN ISOLATED
        # ========================================================

        self.isolated_devices = set()

        # ========================================================
        # LATEST SECURITY STATE
        # ========================================================

        self.device_security_state = {}

    # ========================================================
    # RECEIVE DATA
    # ========================================================

    def receive_data(self, data):

        device_id = data["device_id"]

        print(
            f"\n[GATEWAY] Data received from {device_id}"
        )

        # ====================================================
        # 1. CHECK WHETHER DEVICE IS ALREADY ISOLATED
        # ====================================================

        if device_id in self.isolated_devices:

            print(
                f"[GATEWAY] {device_id} is already isolated."
            )

            print(
                "[GATEWAY] Communication blocked."
            )

            return {
                "decision": "DENY",
                "reason": "Device is already isolated",
                "action": "BLOCK_COMMUNICATION"
            }

        # ====================================================
        # 2. VERIFY MESSAGE AUTHENTICATION
        # ====================================================

        authentication_result = (
            self.verify_message_authentication(data)
        )

        # ====================================================
        # 3. EXTRACT ADAPTIVE ANALYSIS
        # ====================================================

        adaptive_trust = data.get(
            "adaptive_trust",
            {}
        )

        risk_analysis = data.get(
            "risk_analysis",
            {}
        )

        decision_analysis = data.get(
            "decision_analysis",
            {}
        )

        resource_analysis = data.get(
            "resource_analysis",
            {}
        )

        # ====================================================
        # 4. EXTRACT TRUST
        # ====================================================

        trust_score = adaptive_trust.get(
            "trust_score",
            0.0
        )

        trust_status = adaptive_trust.get(
            "trust_status",
            "UNKNOWN"
        )

        # ====================================================
        # 5. EXTRACT RISK
        # ====================================================

        risk_score = risk_analysis.get(
            "risk_score",
            1.0
        )

        risk_status = risk_analysis.get(
            "risk_status",
            "UNKNOWN"
        )

        # ====================================================
        # 6. EXTRACT DECISION
        # ====================================================

        decision = decision_analysis.get(
            "decision",
            "DENY"
        )

        reason = decision_analysis.get(
            "reason",
            "Unknown reason"
        )

        security_action = decision_analysis.get(
            "security_action",
            "BLOCK_REQUEST"
        )

        requires_evidence = decision_analysis.get(
            "requires_evidence",
            False
        )

        requires_isolation = decision_analysis.get(
            "requires_isolation",
            False
        )

        # ====================================================
        # 7. EXTRACT RESOURCE INFORMATION
        # ====================================================

        rcf = resource_analysis.get(
            "rcf",
            0.0
        )

        resource_pressure = resource_analysis.get(
            "resource_pressure",
            0.0
        )

        security_level = resource_analysis.get(
            "security_level",
            "UNKNOWN"
        )

        print("\n[GATEWAY SECURITY ANALYSIS]")

        print(
            "Authentication   :",
            authentication_result["authenticated"]
        )

        print(
            "Trust Score      :",
            trust_score
        )

        print(
            "Trust Status     :",
            trust_status
        )

        print(
            "Risk Score       :",
            risk_score
        )

        print(
            "Risk Status      :",
            risk_status
        )

        print(
            "RCF              :",
            rcf
        )

        print(
            "Resource Pressure:",
            resource_pressure
        )

        print(
            "Security Level   :",
            security_level
        )

        # ====================================================
        # 8. AUTHENTICATION FAILURE
        # ====================================================

        if not authentication_result["authenticated"]:

            print(
                "\n[GATEWAY] Authentication FAILED."
            )

            print(
                "[GATEWAY] Message rejected."
            )

            evidence_event = {

                "event_type":
                    "AUTHENTICATION_FAILURE",

                "device_type":
                    data.get(
                        "device_type",
                        "unknown"
                    ),

                "status":
                    data.get(
                        "status",
                        "unknown"
                    ),

                "malicious_activity":
                    data.get(
                        "malicious_activity",
                        False
                    ),

                "unexpected_network":
                    data.get(
                        "unexpected_network",
                        False
                    ),

                "unauthorized_command":
                    data.get(
                        "unauthorized_command",
                        False
                    ),

                "tampered":
                    data.get(
                        "tampered",
                        False
                    ),

                "attack_type":
                    data.get(
                        "attack_type",
                        "MESSAGE_TAMPERING"
                    ),

                "attack_description":
                    data.get(
                        "attack_description",
                        authentication_result["reason"]
                    ),

                "behavior_score":
                    data.get(
                        "behavior_score",
                        0.0
                    ),

                "context_score":
                    data.get(
                        "context_score",
                        0.0
                    ),

                "risk_score":
                    risk_score,

                "probability_of_compromise":
                    risk_analysis.get(
                        "probability_of_compromise",
                        0.0
                    ),

                "impact":
                    risk_analysis.get(
                        "impact",
                        0.0
                    ),

                "adaptive_trust_score":
                    trust_score,

                "decision":
                    "DENY",

                "security_action":
                    "BLOCK_REQUEST",

                "rcf":
                    rcf,

                "resource_pressure":
                    resource_pressure
            }

            evidence = self.evidence_collector.collect(
                device_id,
                evidence_event,
                trust_score
            )

            forensic_result = (
                self.analyze_forensic_evidence(
                    evidence
                )
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "DENY",

                "reason":
                    "Message authentication failed",

                "security_action":
                    "BLOCK_REQUEST",

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    False,

                "isolated":
                    False,

                "evidence_collected":
                    True,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    "DENY",

                "reason":
                    "Message authentication failed",

                "action":
                    "BLOCK_REQUEST",

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 9. HIGH RISK / ISOLATION
        # ====================================================

        if requires_isolation:

            print(
                "\n[GATEWAY] Security decision requires isolation."
            )

            print(
                "[GATEWAY] Decision:",
                decision
            )

            print(
                "[GATEWAY] Reason:",
                reason
            )

            # ------------------------------------------------
            # Evidence Collection
            # ------------------------------------------------

            evidence = None

            if requires_evidence:

                evidence = (
                    self.collect_forensic_evidence(
                        data
                    )
                )

            # ------------------------------------------------
            # Forensic Analysis
            # ------------------------------------------------

            forensic_result = (
                self.analyze_forensic_evidence(
                    evidence
                )
            )

            # ------------------------------------------------
            # Device Isolation
            # ------------------------------------------------

            self.isolate_device(
                device_id
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    decision,

                "reason":
                    reason,

                "security_action":
                    security_action,

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    True,

                "evidence_collected":
                    evidence is not None,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    decision,

                "reason":
                    reason,

                "action":
                    "ISOLATE_DEVICE",

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 10. EVIDENCE WITHOUT ISOLATION
        # ====================================================

        evidence = None
        forensic_result = None

        if requires_evidence:

            print(
                "\n[GATEWAY] Evidence collection required."
            )

            evidence = (
                self.collect_forensic_evidence(
                    data
                )
            )

            forensic_result = (
                self.analyze_forensic_evidence(
                    evidence
                )
            )

        # ====================================================
        # 11. RESTRICT ACCESS
        # ====================================================

        if decision == "RESTRICT":

            print(
                "\n[GATEWAY] ACCESS RESTRICTED."
            )

            print(
                "[GATEWAY] Reason:",
                reason
            )

            print(
                "[GATEWAY] Action:",
                security_action
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "RESTRICT",

                "reason":
                    reason,

                "security_action":
                    security_action,

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    False,

                "evidence_collected":
                    evidence is not None,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    "RESTRICT",

                "reason":
                    reason,

                "action":
                    security_action,

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 12. DENY REQUEST
        # ====================================================

        if decision == "DENY":

            print(
                "\n[GATEWAY] REQUEST DENIED."
            )

            print(
                "[GATEWAY] Reason:",
                reason
            )

            print(
                "[GATEWAY] Action:",
                security_action
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "DENY",

                "reason":
                    reason,

                "security_action":
                    security_action,

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    False,

                "evidence_collected":
                    evidence is not None,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    "DENY",

                "reason":
                    reason,

                "action":
                    security_action,

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 13. ALLOW REQUEST
        # ====================================================

        if decision == "ALLOW":

            print(
                "\n[GATEWAY] REQUEST ALLOWED."
            )

            print(
                "[GATEWAY] Reason:",
                reason
            )

            print(
                "[GATEWAY] Security Action:",
                security_action
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "ALLOW",

                "reason":
                    reason,

                "security_action":
                    security_action,

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    False,

                "evidence_collected":
                    evidence is not None,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    "ALLOW",

                "reason":
                    reason,

                "action":
                    security_action,

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 14. MONITOR REQUEST
        # ====================================================

        if decision == "MONITOR":

            print(
                "\n[GATEWAY] REQUEST ALLOWED WITH MONITORING."
            )

            print(
                "[GATEWAY] Reason:",
                reason
            )

            print(
                "[GATEWAY] Security Action:",
                security_action
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "MONITOR",

                "reason":
                    reason,

                "security_action":
                    security_action,

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    False,

                "evidence_collected":
                    evidence is not None,

                "forensic_analysis":
                    forensic_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            return {

                "decision":
                    "MONITOR",

                "reason":
                    reason,

                "action":
                    security_action,

                "evidence":
                    evidence,

                "forensic_analysis":
                    forensic_result
            }

        # ====================================================
        # 15. FALLBACK
        # ====================================================

        print(
            "\n[GATEWAY] Unknown decision."
        )

        print(
            "[GATEWAY] Request denied for safety."
        )

        return {

            "decision":
                "DENY",

            "reason":
                "Unknown security decision",

            "action":
                "BLOCK_REQUEST",

            "evidence":
                evidence,

            "forensic_analysis":
                forensic_result
        }

    # ========================================================
    # HMAC VERIFICATION
    # ========================================================

    def verify_message_authentication(
        self,
        data
    ):

        device_id = data.get(
            "device_id"
        )

        received_signature = data.get(
            "message_signature"
        )

        authentication_status = data.get(
            "authentication_status",
            False
        )

        # ----------------------------------------------------
        # Check authentication status
        # ----------------------------------------------------

        if not authentication_status:

            return {

                "authenticated":
                    False,

                "reason":
                    "Sender did not provide authentication"
            }

        # ----------------------------------------------------
        # Signature must exist
        # ----------------------------------------------------

        if received_signature is None:

            return {

                "authenticated":
                    False,

                "reason":
                    "Missing HMAC signature"
            }

        # ----------------------------------------------------
        # Reconstruct originally signed message
        # ----------------------------------------------------

        verification_data = data.copy()

        verification_data.pop(
            "authentication_status",
            None
        )

        verification_data.pop(
            "message_signature",
            None
        )

        # ----------------------------------------------------
        # These fields are generated AFTER HMAC.
        # They must not affect HMAC verification.
        # ----------------------------------------------------

        verification_data.pop(
            "adaptive_trust",
            None
        )

        verification_data.pop(
            "risk_analysis",
            None
        )

        verification_data.pop(
            "decision_analysis",
            None
        )

        verification_data.pop(
            "resource_analysis",
            None
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Do NOT remove:
        #
        # tampered
        # attack_type
        # attack_description
        # malicious_activity
        # unexpected_network
        # unauthorized_command
        #
        # These fields are part of the message when the
        # attack occurs after HMAC generation.
        # ----------------------------------------------------

        verified = self.crypto.verify_hmac(
            device_id,
            verification_data,
            received_signature
        )

        if verified:

            print(
                "\n[GATEWAY] HMAC verification: SUCCESS"
            )

            return {

                "authenticated":
                    True,

                "reason":
                    "Valid HMAC"
            }

        print(
            "\n[GATEWAY] HMAC verification: FAILED"
        )

        return {

            "authenticated":
                False,

            "reason":
                "Invalid HMAC or message tampering detected"
        }

    # ========================================================
    # FORENSIC EVIDENCE COLLECTION
    # ========================================================

    def collect_forensic_evidence(
        self,
        data
    ):

        device_id = data.get(
            "device_id"
        )

        adaptive_trust = data.get(
            "adaptive_trust",
            {}
        )

        risk_analysis = data.get(
            "risk_analysis",
            {}
        )

        decision_analysis = data.get(
            "decision_analysis",
            {}
        )

        resource_analysis = data.get(
            "resource_analysis",
            {}
        )

        trust_score = adaptive_trust.get(
            "trust_score",
            0.0
        )

        event = {

            "event_type":
                "SECURITY_EVENT",

            "device_type":
                data.get(
                    "device_type",
                    "unknown"
                ),

            "status":
                data.get(
                    "status",
                    "unknown"
                ),

            "malicious_activity":
                data.get(
                    "malicious_activity",
                    False
                ),

            "unexpected_network":
                data.get(
                    "unexpected_network",
                    False
                ),

            "unauthorized_command":
                data.get(
                    "unauthorized_command",
                    False
                ),

            "tampered":
                data.get(
                    "tampered",
                    False
                ),

            "attack_type":
                data.get(
                    "attack_type",
                    None
                ),

            "attack_description":
                data.get(
                    "attack_description",
                    None
                ),

            "behavior_score":
                data.get(
                    "behavior_score",
                    0.0
                ),

            "context_score":
                data.get(
                    "context_score",
                    0.0
                ),

            "risk_score":
                risk_analysis.get(
                    "risk_score",
                    0.0
                ),

            "probability_of_compromise":
                risk_analysis.get(
                    "probability_of_compromise",
                    0.0
                ),

            "impact":
                risk_analysis.get(
                    "impact",
                    0.0
                ),

            "adaptive_trust_score":
                trust_score,

            "decision":
                decision_analysis.get(
                    "decision",
                    "UNKNOWN"
                ),

            "security_action":
                decision_analysis.get(
                    "security_action",
                    "UNKNOWN"
                ),

            "rcf":
                resource_analysis.get(
                    "rcf",
                    0.0
                ),

            "resource_pressure":
                resource_analysis.get(
                    "resource_pressure",
                    0.0
                )
        }

        print(
            "\n[GATEWAY] Collecting forensic evidence..."
        )

        evidence = self.evidence_collector.collect(
            device_id,
            event,
            trust_score
        )

        print(
            "[GATEWAY] Forensic evidence stored."
        )

        return evidence

    # ========================================================
    # FORENSIC ANALYSIS
    # ========================================================

    def analyze_forensic_evidence(
        self,
        evidence
    ):

        if evidence is None:

            return None

        print(
            "\n[GATEWAY] Starting forensic analysis..."
        )

        forensic_result = (
            self.forensic_analyzer.analyze(
                evidence
            )
        )

        self.forensic_analyzer.display_analysis(
            forensic_result
        )

        # ====================================================
        # FORENSIC FEEDBACK
        # ====================================================

        history_update = (
            self.update_forensic_security_history(
                forensic_result
            )
        )

        forensic_result[
            "history_update"
        ] = history_update

        device_id = forensic_result.get(
            "device_id",
            "UNKNOWN"
        )

        if device_id in self.device_security_state:

            self.device_security_state[
                device_id
            ][
                "forensic_analysis"
            ] = forensic_result

            self.device_security_state[
                device_id
            ][
                "forensic_history_update"
            ] = history_update

        return forensic_result

    # ========================================================
    # UPDATE FORENSIC SECURITY HISTORY
    # ========================================================

    def update_forensic_security_history(
        self,
        forensic_result
    ):

        if forensic_result is None:

            return None

        device_id = forensic_result.get(
            "device_id"
        )

        if device_id is None:

            return None

        print(
            "\n[GATEWAY] Updating security history "
            "from forensic analysis..."
        )

        history_update = (
            self.history_manager.record_forensic_incident(
                device_id,
                forensic_result
            )
        )

        print(
            "[GATEWAY] Forensic security history updated."
        )

        print(
            "[GATEWAY] Forensic incidents:",
            history_update[
                "forensic_incidents"
            ]
        )

        print(
            "[GATEWAY] Confirmed incidents:",
            history_update[
                "confirmed_incidents"
            ]
        )

        print(
            "[GATEWAY] New incident:",
            history_update[
                "new_incident"
            ]
        )

        print(
            "[GATEWAY] Incident already active:",
            history_update[
                "incident_already_active"
            ]
        )

        print(
            "[GATEWAY] Last severity:",
            history_update[
                "last_severity"
            ]
        )

        return history_update

    # ========================================================
    # DEVICE ISOLATION
    # ========================================================

    def isolate_device(
        self,
        device_id
    ):

        self.isolated_devices.add(
            device_id
        )

        print(
            "\n" + "=" * 70
        )

        print(
            f"[GATEWAY] DEVICE {device_id} ISOLATED"
        )

        print(
            "[GATEWAY] Further communication blocked."
        )

        print(
            "=" * 70
        )

    # ========================================================
    # DEVICE RECOVERY
    # ========================================================

    def recover_device(
        self,
        device_id,
        authentication_result,
        behavior_score,
        context_score,
        risk_score,
        trust_score,
        forensic_result
    ):

        print(
            "\n" + "=" * 70
        )

        print(
            f"[GATEWAY] RECOVERY PROCESS FOR {device_id}"
        )

        print(
            "=" * 70
        )

        # ----------------------------------------------------
        # Device must be isolated first
        # ----------------------------------------------------

        if not self.is_device_isolated(
            device_id
        ):

            print(
                "[RECOVERY] Device is not isolated."
            )

            print(
                "[RECOVERY] Recovery process not required."
            )

            return {

                "device_id":
                    device_id,

                "recovery_status":
                    "NOT_REQUIRED",

                "reason":
                    "Device is not isolated"
            }

        # ----------------------------------------------------
        # Start recovery
        # ----------------------------------------------------

        recovery_start = (
            self.recovery_manager.start_recovery(
                device_id,
                forensic_result or {}
            )
        )

        # ----------------------------------------------------
        # Re-authentication
        # ----------------------------------------------------

        reauthenticated = (
            self.recovery_manager.reauthenticate_device(
                device_id,
                authentication_result
            )
        )

        if not reauthenticated:

            result = {

                "device_id":
                    device_id,

                "recovery_status":
                    "RECOVERY_FAILED",

                "reason":
                    "Device re-authentication failed",

                "authentication":
                    False,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

            if device_id not in self.device_security_state:
                self.device_security_state[
                    device_id
                ] = {}

            self.device_security_state[
                device_id
            ][
                "recovery_result"
            ] = result

            self.recovery_manager.complete_recovery(
                device_id,
                result
            )

            return result

        # ----------------------------------------------------
        # Security re-evaluation
        # ----------------------------------------------------

        recovery_result = (
            self.recovery_manager.reevaluate_device(
                device_id,
                behavior_score,
                context_score,
                risk_score,
                trust_score
            )
        )

        recovery_result[
            "authentication"
        ] = True

        recovery_result[
            "recovery_start"
        ] = recovery_start

        # ----------------------------------------------------
        # Complete recovery
        # ----------------------------------------------------

        recovery_result = (
            self.recovery_manager.complete_recovery(
                device_id,
                recovery_result
            )
        )

        # ----------------------------------------------------
        # Successful recovery
        # ----------------------------------------------------

        if (
            recovery_result[
                "recovery_status"
            ]
            == "RECOVERY_SUCCESSFUL"
        ):

            self.isolated_devices.discard(
                device_id
            )

            # ====================================================
            # IMPORTANT FORENSIC FIX
            # ====================================================
            #
            # The incident remains in historical records.
            #
            # But the active incident is now resolved.
            #
            # If the same device is attacked again later,
            # HistoryManager will count that as a NEW incident.
            # ====================================================

            attack_type = None

            if forensic_result is not None:

                attack_type = forensic_result.get(
                    "attack_type"
                )

            self.history_manager.resolve_forensic_incident(
                device_id,
                attack_type
            )

            self.device_security_state[
                device_id
            ] = {

                "decision":
                    "MONITOR",

                "reason":
                    "Device successfully recovered",

                "security_action":
                    "ALLOW_WITH_MONITORING",

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    True,

                "isolated":
                    False,

                "recovery_status":
                    "RECOVERY_SUCCESSFUL",

                "forensic_analysis":
                    forensic_result,

                "recovery_result":
                    recovery_result,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }

        # ----------------------------------------------------
        # Failed recovery
        # ----------------------------------------------------

        else:

            if device_id not in self.device_security_state:

                self.device_security_state[
                    device_id
                ] = {}

            self.device_security_state[
                device_id
            ][
                "recovery_result"
            ] = recovery_result

            self.device_security_state[
                device_id
            ][
                "isolated"
            ] = True

        return recovery_result

    # ========================================================
    # CHECK DEVICE ISOLATION
    # ========================================================

    def is_device_isolated(
        self,
        device_id
    ):

        return (
            device_id
            in self.isolated_devices
        )

    # ========================================================
    # GET DEVICE SECURITY STATE
    # ========================================================

    def get_device_security_state(
        self,
        device_id
    ):

        return self.device_security_state.get(

            device_id,

            {
                "decision":
                    "UNKNOWN",

                "reason":
                    "No security state available"
            }
        )

    # ========================================================
    # GET ALL ISOLATED DEVICES
    # ========================================================

    def get_isolated_devices(
        self
    ):

        return list(
            self.isolated_devices
        )

    # ========================================================
    # GET RECOVERY HISTORY
    # ========================================================

    def get_recovery_history(
        self,
        device_id
    ):

        return (
            self.recovery_manager
            .get_recovery_history(
                device_id
            )
        )

    # ========================================================
    # GET DEVICES UNDER RECOVERY
    # ========================================================

    def get_devices_under_recovery(
        self
    ):

        return (
            self.recovery_manager
            .get_devices_under_recovery()
        )