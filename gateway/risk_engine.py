class RiskEngine:

    def __init__(self):

        # Weights for risk components
        self.behavior_weight = 0.30
        self.context_weight = 0.20
        self.vulnerability_weight = 0.20
        self.sensitivity_weight = 0.15
        self.exposure_weight = 0.15

    # --------------------------------------------------------
    # Vulnerability
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Resource Sensitivity
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Exposure
    # --------------------------------------------------------

    def calculate_exposure(self, data):

        exposure = 0.20

        if data.get("unexpected_network", False):
            exposure += 0.30

        if data.get("unauthorized_command", False):
            exposure += 0.30

        if data.get("malicious_activity", False):
            exposure += 0.20

        return min(1.0, exposure)

    # --------------------------------------------------------
    # Probability of Compromise
    # --------------------------------------------------------

    def calculate_probability_of_compromise(
        self,
        behavior_score,
        context_score,
        vulnerability,
        exposure
    ):

        behavior_anomaly = 1 - behavior_score
        context_anomaly = 1 - context_score

        probability = (
            0.35 * behavior_anomaly
            + 0.20 * context_anomaly
            + 0.20 * vulnerability
            + 0.25 * exposure
        )

        return round(
            max(0.0, min(1.0, probability)),
            3
        )

    # --------------------------------------------------------
    # Impact
    # --------------------------------------------------------

    def calculate_impact(
        self,
        device,
        resource_sensitivity
    ):

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

        impact = (
            0.60 * criticality
            + 0.40 * resource_sensitivity
        )

        return round(
            max(0.0, min(1.0, impact)),
            3
        )

    # --------------------------------------------------------
    # Final Risk
    # --------------------------------------------------------

    def calculate_risk(
        self,
        behavior_score,
        context_score,
        device,
        data
    ):

        vulnerability = self.calculate_vulnerability(
            device
        )

        resource_sensitivity = (
            self.calculate_resource_sensitivity(data)
        )

        exposure = self.calculate_exposure(
            data
        )

        probability = (
            self.calculate_probability_of_compromise(
                behavior_score,
                context_score,
                vulnerability,
                exposure
            )
        )

        impact = self.calculate_impact(
            device,
            resource_sensitivity
        )

        risk = probability * impact

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

    # --------------------------------------------------------
    # Risk Status
    # --------------------------------------------------------

    def get_risk_status(self, risk_score):

        if risk_score < 0.30:
            return "LOW"

        elif risk_score < 0.60:
            return "MODERATE"

        elif risk_score < 0.80:
            return "HIGH"

        else:
            return "CRITICAL"