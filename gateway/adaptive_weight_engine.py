class AdaptiveWeightEngine:

    def __init__(self):

        # ----------------------------------------------------
        # Baseline weights
        # ----------------------------------------------------
        #
        # These are initial experimental values.
        # They will later be tuned through experiments.
        #
        # B = Behavior
        # C = Context
        # H = History
        # R = Risk
        # ----------------------------------------------------

        self.base_weights = {
            "behavior": 0.25,
            "context": 0.20,
            "history": 0.30,
            "risk": 0.25
        }


    # ========================================================
    # NORMALIZE WEIGHTS
    # ========================================================

    def normalize_weights(self, weights):

        total = sum(weights.values())

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
        previous_compromise=False
    ):

        # ----------------------------------------------------
        # Start from baseline weights
        # ----------------------------------------------------

        weights = self.base_weights.copy()


        # ----------------------------------------------------
        # 1. BEHAVIOR ADAPTATION
        # ----------------------------------------------------

        behavior_anomaly = 1 - behavior_score

        weights["behavior"] *= (
            1 + behavior_anomaly
        )


        # ----------------------------------------------------
        # 2. CONTEXT ADAPTATION
        # ----------------------------------------------------

        context_anomaly = 1 - context_score

        weights["context"] *= (
            1 + context_anomaly
        )


        # ----------------------------------------------------
        # 3. HISTORY ADAPTATION
        # ----------------------------------------------------

        history_anomaly = 1 - history_score

        weights["history"] *= (
            1 + history_anomaly
        )


        # ----------------------------------------------------
        # 4. RISK ADAPTATION
        # ----------------------------------------------------

        weights["risk"] *= (
            1 + risk_score
        )


        # ----------------------------------------------------
        # 5. PREVIOUS COMPROMISE
        # ----------------------------------------------------

        if previous_compromise:

            weights["history"] *= 1.25

            weights["risk"] *= 1.20


        # ----------------------------------------------------
        # 6. NORMALIZE
        # ----------------------------------------------------

        adaptive_weights = (
            self.normalize_weights(weights)
        )


        return adaptive_weights


    # ========================================================
    # DETERMINE DOMINANT FACTOR
    # ========================================================

    def get_dominant_factor(
        self,
        adaptive_weights
    ):

        dominant_factor = max(
            adaptive_weights,
            key=adaptive_weights.get
        )

        return dominant_factor


    # ========================================================
    # ANALYZE ADAPTATION
    # ========================================================

    def analyze(
        self,
        behavior_score,
        context_score,
        history_score,
        risk_score,
        previous_compromise=False
    ):

        adaptive_weights = (
            self.calculate_adaptive_weights(

                behavior_score=behavior_score,

                context_score=context_score,

                history_score=history_score,

                risk_score=risk_score,

                previous_compromise=previous_compromise
            )
        )


        dominant_factor = (
            self.get_dominant_factor(
                adaptive_weights
            )
        )


        return {
            "behavior_weight":
                adaptive_weights["behavior"],

            "context_weight":
                adaptive_weights["context"],

            "history_weight":
                adaptive_weights["history"],

            "risk_weight":
                adaptive_weights["risk"],

            "dominant_factor":
                dominant_factor
        }