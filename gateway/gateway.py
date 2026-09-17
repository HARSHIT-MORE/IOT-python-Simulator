import time


class Gateway:

    def __init__(
        self,
        trust_manager,
        evidence_collector,
        crypto
    ):

        self.trust_manager = trust_manager
        self.evidence_collector = evidence_collector
        self.crypto = crypto

        # Devices that have been isolated
        self.isolated_devices = set()

        # Store latest security state of every device
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
            self.verify_message_authentication(
                data
            )
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
            "No valid decision available"
        )

        security_action = decision_analysis.get(
            "security_action",
            "BLOCK_REQUEST"
        )

        requires_evidence = decision_analysis.get(
            "requires_evidence",
            True
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
            1.0
        )

        security_level = resource_analysis.get(
            "security_level",
            "UNKNOWN"
        )


        # ====================================================
        # 8. DISPLAY GATEWAY SECURITY ANALYSIS
        # ====================================================

        print("\n[GATEWAY SECURITY ANALYSIS]")

        print(
            "Authentication :",
            authentication_result["authenticated"]
        )

        print(
            "Adaptive Trust  :",
            trust_score
        )

        print(
            "Trust Status    :",
            trust_status
        )

        print(
            "Risk Score      :",
            risk_score
        )

        print(
            "Risk Status     :",
            risk_status
        )

        print(
            "RCF             :",
            rcf
        )

        print(
            "Resource Pressure:",
            resource_pressure
        )

        print(
            "Security Level  :",
            security_level
        )


        # ====================================================
        # 9. AUTHENTICATION FAILURE
        # ====================================================

        if not authentication_result["authenticated"]:

            print(
                "\n[GATEWAY] Authentication FAILED."
            )

            print(
                "[GATEWAY] Message rejected."
            )


            evidence = self.evidence_collector.collect(
                device_id,
                "HMAC authentication failure",
                trust_score
            )


            self.device_security_state[
                device_id
            ] = {

                "decision": "DENY",

                "reason":
                    "Message authentication failed",

                "trust_score":
                    trust_score,

                "risk_score":
                    risk_score,

                "authentication":
                    False,

                "timestamp":
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
            }


            return {

                "decision": "DENY",

                "reason":
                    "Message authentication failed",

                "action":
                    "BLOCK_REQUEST",

                "evidence":
                    evidence
            }


        # ====================================================
        # 10. HIGH RISK / COMPROMISED DEVICE
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
                    evidence
            }


        # ====================================================
        # 11. EVIDENCE WITHOUT ISOLATION
        # ====================================================

        evidence = None

        if requires_evidence:

            print(
                "\n[GATEWAY] Evidence collection required."
            )

            evidence = (
                self.collect_forensic_evidence(
                    data
                )
            )


        # ====================================================
        # 12. RESTRICT ACCESS
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
                    evidence
            }


        # ====================================================
        # 13. DENY REQUEST
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
                    evidence
            }


        # ====================================================
        # 14. ALLOW REQUEST
        # ====================================================

        if decision == "ALLOW":

            print(
                "\n[GATEWAY] REQUEST ALLOWED."
            )

            print(
                "[GATEWAY] High trust + acceptable risk."
            )

            print(
                "[GATEWAY] Action:",
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
                    evidence
            }


        # ====================================================
        # 15. MONITOR REQUEST
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
                    evidence
            }


        # ====================================================
        # 16. FALLBACK
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
                evidence
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
        # Check whether sender generated authentication
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
        # IMPORTANT HMAC FIX
        #
        # The HMAC was generated in main.py BEFORE these
        # gateway analysis fields were added:
        #
        # adaptive_trust
        # risk_analysis
        # decision_analysis
        # resource_analysis
        #
        # Therefore these fields must be removed before
        # verification.
        #
        # DO NOT remove attack/tampering fields here.
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
        # Verify HMAC
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
            "\n" + "!" * 70
        )

        print(
            f"[GATEWAY] DEVICE {device_id} ISOLATED"
        )

        print(
            "[GATEWAY] Further communication blocked."
        )

        print(
            "!" * 70
        )


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

    def get_isolated_devices(self):

        return list(
            self.isolated_devices
        )