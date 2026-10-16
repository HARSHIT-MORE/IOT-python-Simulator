#scores tell us how good/bad a factor is, 
# while the weights tell us how much importance that factor should have in the final trust calculation.

class AdaptiveWeightEngine:

    def __init__(self):

        # ====================================================
        # BASE WEIGHTS
        # ====================================================

        self.base_weights = {

            "behavior":
                0.25,

            "context":
                0.20,

            "history":
                0.30,

            "risk":
                0.25
        }

        # ====================================================
        # FORENSIC FEEDBACK PARAMETERS
        # ====================================================

        self.forensic_history_factor = 1.25

        self.forensic_risk_factor = 1.20

        self.high_severity_history_factor = 1.15

        self.high_severity_risk_factor = 1.15

    # ========================================================
    # NORMALIZE WEIGHTS
    # ========================================================

    def normalize_weights(
        self,
        weights
    ):

        total = sum(
            weights.values()
        )

        if total == 0:

            return self.base_weights.copy()

        normalized_weights = {}

        for key, value in weights.items():

            normalized_weights[key] = round(
                value / total,
                3
            )

        return normalized_weights

    # ========================================================
    # CALCULATE ADAPTIVE WEIGHTS
    # ========================================================

    def calculate_adaptive_weights(

        self,

        behavior_score,

        context_score,

        history_score,

        risk_score,

        forensic_incident=False,

        forensic_severity="UNKNOWN"
    ):

        weights = (
            self.base_weights.copy()
        )

        # ----------------------------------------------------
        # Behavior anomaly
        # ----------------------------------------------------

        behavior_anomaly = (
            1 - behavior_score
        )

        weights[
            "behavior"
        ] *= (
            1
            +
            behavior_anomaly
        )

        # ----------------------------------------------------
        # Context anomaly
        # ----------------------------------------------------

        context_anomaly = (
            1 - context_score
        )

        weights[
            "context"
        ] *= (
            1
            +
            context_anomaly
        )

        # ----------------------------------------------------
        # Historical weakness
        # ----------------------------------------------------

        history_anomaly = (
            1 - history_score
        )

        weights[
            "history"
        ] *= (
            1
            +
            history_anomaly
        )

        # ----------------------------------------------------
        # Current risk
        # ----------------------------------------------------

        weights[
            "risk"
        ] *= (
            1
            +
            risk_score
        )

        # ====================================================
        # FORENSIC FEEDBACK
        # ====================================================

        if forensic_incident:

            weights[
                "history"
            ] *= (
                self.forensic_history_factor
            )

            weights[
                "risk"
            ] *= (
                self.forensic_risk_factor
            )

        # ----------------------------------------------------
        # High-severity forensic incident
        # ----------------------------------------------------

        if forensic_severity == "HIGH": #additional increase

            weights[
                "history"
            ] *= (
                self.high_severity_history_factor
            )

            weights[
                "risk"
            ] *= (
                self.high_severity_risk_factor
            )

        # ----------------------------------------------------
        # Normalize
        # ----------------------------------------------------

        return self.normalize_weights(
            weights
        )

    # ========================================================
    # DOMINANT FACTOR
    # ========================================================

    def get_dominant_factor(
        self,
        adaptive_weights
    ):

        return max(
            adaptive_weights,
            key=adaptive_weights.get
        )

    # ========================================================
    # COMPLETE ANALYSIS
    # ========================================================

    def analyze(

        self,

        behavior_score,

        context_score,

        history_score,

        risk_score,

        forensic_incident=False,

        forensic_severity="UNKNOWN"
    ):

        adaptive_weights = (

            self.calculate_adaptive_weights(

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

        dominant_factor = (

            self.get_dominant_factor(
                adaptive_weights
            )
        )

        return {

            "behavior_weight":
                adaptive_weights[
                    "behavior"
                ],

            "context_weight":
                adaptive_weights[
                    "context"
                ],

            "history_weight":
                adaptive_weights[
                    "history"
                ],

            "risk_weight":
                adaptive_weights[
                    "risk"
                ],

            "dominant_factor":
                dominant_factor,

            "forensic_feedback":
                forensic_incident,

            "forensic_severity":
                forensic_severity
        }