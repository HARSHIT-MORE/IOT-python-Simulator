class DecisionEngine:

    def __init__(self):

        # ============================================================
        # DEVICE CRITICALITY
        # ============================================================

        self.criticality_map = {
            "smart_clock": 0.30,
            "temperature_sensor": 0.20,
            "motion_sensor": 0.40,
            "camera": 0.80
        }

    # ================================================================
    # DEVICE CRITICALITY
    # ================================================================

    def get_criticality(self, device_type):

        return self.criticality_map.get(
            device_type,
            0.50
        )

    # ================================================================
    # DECISION ENGINE
    # ================================================================

    def analyze(
        self,
        trust_score,
        risk_score,
        rcf,
        resource_pressure,
        device_type
    ):

        criticality = self.get_criticality(
            device_type
        )

        # ============================================================
        # CRITICAL RISK
        # ============================================================

        if risk_score >= 0.90:

            return {

                "decision":
                    "DENY",

                "reason":
                    "Critical risk score",

                "security_action":
                    "ISOLATE_DEVICE",

                "requires_evidence":
                    True,

                "requires_isolation":
                    True,

                "criticality":
                    criticality
            }

        # ============================================================
        # HIGH RISK
        # ============================================================

        if risk_score >= 0.70:

            return {

                "decision":
                    "DENY",

                "reason":
                    "High risk score",

                "security_action":
                    "BLOCK_REQUEST",

                "requires_evidence":
                    True,

                "requires_isolation":
                    True,

                "criticality":
                    criticality
            }

        # ============================================================
        # VERY LOW TRUST
        # ============================================================

        if trust_score < 0.40:

            return {

                "decision":
                    "RESTRICT",

                "reason":
                    "Low adaptive trust",

                "security_action":
                    "BLOCK_REQUEST",

                "requires_evidence":
                    True,

                "requires_isolation":
                    False,

                "criticality":
                    criticality
            }

        # ============================================================
        # MODERATE TRUST / ELEVATED RISK
        # ============================================================

        if (
            trust_score < 0.60
            or risk_score >= 0.50
        ):

            return {

                "decision":
                    "RESTRICT",

                "reason":
                    "Moderate trust or elevated risk",

                "security_action":
                    "LIMIT_ACCESS_AND_MONITOR",

                "requires_evidence":
                    True,

                "requires_isolation":
                    False,

                "criticality":
                    criticality
            }

        # ============================================================
        # HIGH RESOURCE PRESSURE
        # ============================================================

        if resource_pressure >= 0.80:

            return {

                "decision":
                    "MONITOR",

                "reason":
                    "High resource pressure",

                "security_action":
                    "LIGHTWEIGHT_VERIFICATION",

                "requires_evidence":
                    False,

                "requires_isolation":
                    False,

                "criticality":
                    criticality
            }

        # ============================================================
        # HIGH TRUST + LOW RISK
        # ============================================================

        if (
            trust_score >= 0.75
            and risk_score < 0.30
        ):

            return {

                "decision":
                    "ALLOW",

                "reason":
                    "High trust and low risk",

                "security_action":
                    "ALLOW_REQUEST",

                "requires_evidence":
                    False,

                "requires_isolation":
                    False,

                "criticality":
                    criticality
            }

        # ============================================================
        # DEFAULT
        # ============================================================

        return {

            "decision":
                "MONITOR",

            "reason":
                "Normal trust with moderate uncertainty",

            "security_action":
                "ALLOW_WITH_MONITORING",

            "requires_evidence":
                False,

            "requires_isolation":
                False,

            "criticality":
                criticality
        }