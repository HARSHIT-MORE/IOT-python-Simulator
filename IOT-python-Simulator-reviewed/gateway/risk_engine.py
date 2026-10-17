class RiskEngine:

    def __init__(self):

        # ========================================================
        # PROBABILITY OF COMPROMISE WEIGHTS
        # ========================================================
        #
        # These weights determine how strongly each factor
        # contributes to the probability that a device/request
        # is compromised.
        #
        # Total = 1.0
        #

        self.behavior_weight = 0.35
        self.context_weight = 0.20
        self.vulnerability_weight = 0.20
        self.exposure_weight = 0.25

        # ========================================================
        # IMPACT WEIGHTS
        # ========================================================
        #
        # Impact represents how serious the consequences would
        # be if compromise occurs.
        #
        # Total = 1.0
        #

        self.criticality_weight = 0.60
        self.sensitivity_weight = 0.40


    # ============================================================
    # Vulnerability
    # ============================================================

    def calculate_vulnerability(self, device):

        vulnerability_map = {
            "smart_clock": 0.30,
            "temperature_sensor": 0.20,
            "motion_sensor": 0.30,
            "camera": 0.60
        }

        return vulnerability_map.get(
            device.device_type,
            0.50
        )


    # ============================================================
    # Resource Sensitivity
    # ============================================================

    def calculate_resource_sensitivity(self, data):

        requested_resource = data.get(
            "requested_resource",
            "sensor_data"
        )

        sensitivity_map = {
            "sensor_data": 0.20,
            "time_data": 0.10,
            "image_data": 0.80,
            "control_command": 0.90,
            "admin_data": 1.00
        }

        return sensitivity_map.get(
            requested_resource,
            0.50
        )


    # ============================================================
    # Exposure
    # ============================================================

    def calculate_exposure(self, data):

        # Baseline exposure
        exposure = 0.20

        # Unexpected network communication increases exposure
        if data.get("unexpected_network", False):
            exposure += 0.30

        # Unauthorized commands indicate greater exposure
        if data.get("unauthorized_command", False):
            exposure += 0.30

        # Malicious activity provides additional evidence
        if data.get("malicious_activity", False):
            exposure += 0.20

        return round(
            min(1.0, exposure),
            3
        )


    # ============================================================
    # Probability of Compromise
    # ============================================================

    def calculate_probability_of_compromise(
        self,
        behavior_score,
        context_score,
        vulnerability,
        exposure
    ):

        # --------------------------------------------------------
        # Convert trust-like scores into anomaly scores
        # --------------------------------------------------------

        behavior_anomaly = 1.0 - behavior_score
        context_anomaly = 1.0 - context_score

        # --------------------------------------------------------
        # Weighted probability model
        # --------------------------------------------------------

        probability = (
            self.behavior_weight * behavior_anomaly
            + self.context_weight * context_anomaly
            + self.vulnerability_weight * vulnerability
            + self.exposure_weight * exposure
        )

        # Keep probability within [0, 1]
        probability = max(
            0.0,
            min(1.0, probability)
        )

        return round(
            probability,
            3
        )


    # ============================================================
    # Impact
    # ============================================================

    def calculate_impact(
        self,
        device,
        resource_sensitivity
    ):

        # --------------------------------------------------------
        # Device criticality
        # --------------------------------------------------------

        device_criticality = {
            "smart_clock": 0.30,
            "temperature_sensor": 0.20,
            "motion_sensor": 0.40,
            "camera": 0.80
        }

        criticality = device_criticality.get(
            device.device_type,
            0.50
        )

        # --------------------------------------------------------
        # Impact calculation
        # --------------------------------------------------------
        #
        # Criticality represents importance of the device.
        #
        # Resource sensitivity represents how sensitive the
        # requested resource is.
        #

        impact = (
            self.criticality_weight * criticality
            + self.sensitivity_weight * resource_sensitivity
        )

        impact = max(
            0.0,
            min(1.0, impact)
        )

        return round(
            impact,
            3
        )


    # ============================================================
    # Final Risk
    # ============================================================

    def calculate_risk(
        self,
        behavior_score,
        context_score,
        device,
        data
    ):

        # --------------------------------------------------------
        # 1. Vulnerability
        # --------------------------------------------------------

        vulnerability = self.calculate_vulnerability(
            device
        )

        # --------------------------------------------------------
        # 2. Resource sensitivity
        # --------------------------------------------------------

        resource_sensitivity = (
            self.calculate_resource_sensitivity(
                data
            )
        )

        # --------------------------------------------------------
        # 3. Exposure
        # --------------------------------------------------------

        exposure = self.calculate_exposure(
            data
        )

        # --------------------------------------------------------
        # 4. Probability of compromise
        # --------------------------------------------------------

        probability = (
            self.calculate_probability_of_compromise(
                behavior_score=behavior_score,
                context_score=context_score,
                vulnerability=vulnerability,
                exposure=exposure
            )
        )

        # --------------------------------------------------------
        # 5. Impact
        # --------------------------------------------------------

        impact = self.calculate_impact(
            device=device,
            resource_sensitivity=resource_sensitivity
        )

        # --------------------------------------------------------
        # 6. Final risk
        # --------------------------------------------------------
        #
        # Risk = Probability × Impact
        #

        risk = probability * impact

        risk = max(
            0.0,
            min(1.0, risk)
        )

        return {

            "probability_of_compromise": round(
                probability,
                3
            ),

            "impact": round(
                impact,
                3
            ),

            "vulnerability": round(
                vulnerability,
                3
            ),

            "resource_sensitivity": round(
                resource_sensitivity,
                3
            ),

            "exposure": round(
                exposure,
                3
            ),

            "risk_score": round(
                risk,
                3
            ),

            "risk_status": self.get_risk_status(
                risk
            )
        }


    # ============================================================
    # Risk Status
    # ============================================================

    def get_risk_status(self, risk_score):

        if risk_score < 0.30:
            return "LOW"

        elif risk_score < 0.60:
            return "MODERATE"

        elif risk_score < 0.80:
            return "HIGH"

        else:
            return "CRITICAL"