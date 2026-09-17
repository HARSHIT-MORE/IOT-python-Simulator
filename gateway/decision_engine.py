class DecisionEngine:

    def __init__(self):

        # Initial experimental thresholds.
        # These values should later be tuned using experiments.

        self.emergency_risk_threshold = 0.90

        self.allow_trust_threshold = 0.75
        self.allow_risk_threshold = 0.30

        self.monitor_trust_threshold = 0.60
        self.monitor_risk_threshold = 0.50

        self.restrict_trust_threshold = 0.40
        self.restrict_risk_threshold = 0.70

    def get_device_criticality(self, device_type):

        criticality_map = {
            "temperature_sensor": 0.20,
            "smart_clock": 0.30,
            "motion_sensor": 0.40,
            "camera": 0.80
        }

        return criticality_map.get(device_type, 0.50)

    def make_decision(
        self,
        trust_score,
        risk_score,
        rcf,
        resource_pressure,
        device_type,
        compromised=False
    ):

        criticality = self.get_device_criticality(device_type)

        # --------------------------------------------------
        # 1. Emergency condition
        # --------------------------------------------------

        if compromised or risk_score >= self.emergency_risk_threshold:

            return {
                "decision": "DENY_ISOLATE",
                "criticality": criticality,
                "reason": (
                    "Device is compromised or has critical risk."
                ),
                "security_action": "BLOCK_COMMUNICATION",
                "requires_evidence": True,
                "requires_isolation": True
            }

        # --------------------------------------------------
        # 2. High trust + low risk
        # --------------------------------------------------

        if (
            trust_score >= self.allow_trust_threshold
            and risk_score < self.allow_risk_threshold
        ):

            # If resource pressure is very high,
            # avoid unnecessary security overhead.

            if resource_pressure >= 0.80:

                return {
                    "decision": "MONITOR",
                    "criticality": criticality,
                    "reason": (
                        "Trust is high and risk is low, "
                        "but current resource pressure is critical."
                    ),
                    "security_action": "LIGHTWEIGHT_MONITORING",
                    "requires_evidence": False,
                    "requires_isolation": False
                }

            return {
                "decision": "ALLOW",
                "criticality": criticality,
                "reason": (
                    "High trust and low risk."
                ),
                "security_action": "NORMAL_OPERATION",
                "requires_evidence": False,
                "requires_isolation": False
            }

        # --------------------------------------------------
        # 3. Moderate trust / moderate risk
        # --------------------------------------------------

        if (
            trust_score >= self.monitor_trust_threshold
            and risk_score < self.monitor_risk_threshold
        ):

            return {
                "decision": "MONITOR",
                "criticality": criticality,
                "reason": (
                    "Moderate risk detected while trust "
                    "remains acceptable."
                ),
                "security_action": "INCREASE_MONITORING",
                "requires_evidence": True,
                "requires_isolation": False
            }

        # --------------------------------------------------
        # 4. Suspicious device
        # --------------------------------------------------

        if (
            trust_score >= self.restrict_trust_threshold
            and risk_score < self.restrict_risk_threshold
        ):

            return {
                "decision": "RESTRICT",
                "criticality": criticality,
                "reason": (
                    "Trust is reduced or risk is elevated."
                ),
                "security_action": "LIMIT_RESOURCE_ACCESS",
                "requires_evidence": True,
                "requires_isolation": False
            }

        # --------------------------------------------------
        # 5. Default deny
        # --------------------------------------------------

        return {
            "decision": "DENY_ISOLATE",
            "criticality": criticality,
            "reason": (
                "Trust is too low or risk is too high."
            ),
            "security_action": "BLOCK_COMMUNICATION",
            "requires_evidence": True,
            "requires_isolation": True
        }

    def analyze(
        self,
        trust_score,
        risk_score,
        rcf,
        resource_pressure,
        device_type,
        compromised=False
    ):

        return self.make_decision(
            trust_score=trust_score,
            risk_score=risk_score,
            rcf=rcf,
            resource_pressure=resource_pressure,
            device_type=device_type,
            compromised=compromised
        )