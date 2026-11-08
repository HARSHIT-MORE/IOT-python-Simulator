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
        """Apply the existing thresholds and return an auditable rule trace."""
        criticality = self.get_criticality(device_type)

        def result(decision, reason, security_action, requires_evidence,
                   requires_isolation, rule_id, matched_conditions):
            return {
                "decision": decision,
                "reason": reason,
                "security_action": security_action,
                "requires_evidence": requires_evidence,
                "requires_isolation": requires_isolation,
                "criticality": criticality,
                "decision_rule": rule_id,
                "matched_conditions": matched_conditions,
                "decision_basis": {
                    "trust_score": trust_score,
                    "risk_score": risk_score,
                    "resource_pressure": resource_pressure,
                    "rcf": rcf,
                    "thresholds": {
                        "critical_risk": 0.90,
                        "high_risk": 0.70,
                        "very_low_trust": 0.40,
                        "moderate_trust": 0.60,
                        "elevated_risk": 0.50,
                        "high_resource_pressure": 0.80,
                        "allow_min_trust": 0.75,
                        "allow_max_risk_exclusive": 0.30,
                    },
                },
            }

        # Preserve existing rule order and thresholds.
        if risk_score >= 0.90:
            return result(
                "DENY", "Critical risk score", "ISOLATE_DEVICE", True, True,
                "RISK_CRITICAL_GE_0_90",
                [f"risk_score={risk_score:.3f} >= 0.900"],
            )

        if risk_score >= 0.70:
            return result(
                "DENY", "High risk score", "BLOCK_REQUEST", True, True,
                "RISK_HIGH_GE_0_70",
                [f"risk_score={risk_score:.3f} >= 0.700"],
            )

        if trust_score < 0.40:
            return result(
                "RESTRICT", "Low adaptive trust", "BLOCK_REQUEST", True, False,
                "TRUST_VERY_LOW_LT_0_40",
                [f"trust_score={trust_score:.3f} < 0.400"],
            )

        if trust_score < 0.60 or risk_score >= 0.50:
            matched = []
            if trust_score < 0.60:
                matched.append(f"trust_score={trust_score:.3f} < 0.600")
            if risk_score >= 0.50:
                matched.append(f"risk_score={risk_score:.3f} >= 0.500")
            return result(
                "RESTRICT", "Moderate trust or elevated risk",
                "LIMIT_ACCESS_AND_MONITOR", True, False,
                "TRUST_MODERATE_OR_RISK_ELEVATED", matched,
            )

        if resource_pressure >= 0.80:
            return result(
                "MONITOR", "High resource pressure",
                "LIGHTWEIGHT_VERIFICATION", False, False,
                "RESOURCE_PRESSURE_GE_0_80",
                [f"resource_pressure={resource_pressure:.3f} >= 0.800"],
            )

        if trust_score >= 0.75 and risk_score < 0.30:
            return result(
                "ALLOW", "High trust and low risk", "ALLOW_REQUEST", False, False,
                "TRUST_GE_0_75_AND_RISK_LT_0_30",
                [f"trust_score={trust_score:.3f} >= 0.750",
                 f"risk_score={risk_score:.3f} < 0.300"],
            )

        return result(
            "MONITOR", "Normal trust with moderate uncertainty",
            "ALLOW_WITH_MONITORING", False, False,
            "DEFAULT_MONITOR",
            ["No earlier decision rule matched"],
        )

