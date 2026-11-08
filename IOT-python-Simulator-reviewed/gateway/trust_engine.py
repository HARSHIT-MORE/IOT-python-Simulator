class TrustEngine:

    def __init__(self):
        pass

    # ========================================================
    # CALCULATE ADAPTIVE TRUST SCORE
    # ========================================================

    def calculate_trust(
        self,
        behavior_score,
        context_score,
        history_score,
        risk_score,
        adaptive_weights
    ):

        # ----------------------------------------------------
        # Extract adaptive weights
        # ----------------------------------------------------

        behavior_weight = (
            adaptive_weights["behavior_weight"]
        )

        context_weight = (
            adaptive_weights["context_weight"]
        )

        history_weight = (
            adaptive_weights["history_weight"]
        )

        risk_weight = (
            adaptive_weights["risk_weight"]
        )


        # ----------------------------------------------------
        # Convert risk into a positive trust contribution
        # ----------------------------------------------------

        risk_trust = 1 - risk_score


        # ----------------------------------------------------
        # Adaptive Trust Equation
        # ----------------------------------------------------

        trust_score = (

            behavior_weight * behavior_score

            +

            context_weight * context_score

            +

            history_weight * history_score

            +

            risk_weight * risk_trust
        )


        # ----------------------------------------------------
        # Keep score between 0 and 1
        # ----------------------------------------------------

        trust_score = max(
            0.0,
            min(1.0, trust_score)
        )


        return round(
            trust_score,
            3
        )


    # ========================================================
    # TRUST STATUS
    # ========================================================

    def get_trust_status(
        self,
        trust_score
    ):

        if trust_score >= 0.80:

            return "TRUSTED"

        elif trust_score >= 0.60:

            return "ACCEPTABLE"

        elif trust_score >= 0.40:

            return "SUSPICIOUS"

        else:

            return "UNTRUSTED"


    # ========================================================
    # COMPLETE ANALYSIS
    # ========================================================

    def analyze(
        self,
        behavior_score,
        context_score,
        history_score,
        risk_score,
        adaptive_weights
    ):

        trust_score = self.calculate_trust(

            behavior_score=behavior_score,

            context_score=context_score,

            history_score=history_score,

            risk_score=risk_score,

            adaptive_weights=adaptive_weights
        )


        trust_status = self.get_trust_status(
            trust_score
        )


        return {

            "trust_score":
                trust_score,

            "trust_status":
                trust_status,

            "behavior_contribution":
                round(
                    adaptive_weights[
                        "behavior_weight"
                    ] * behavior_score,
                    3
                ),

            "context_contribution":
                round(
                    adaptive_weights[
                        "context_weight"
                    ] * context_score,
                    3
                ),

            "history_contribution":
                round(
                    adaptive_weights[
                        "history_weight"
                    ] * history_score,
                    3
                ),

            "risk_contribution":
                round(
                    adaptive_weights[
                        "risk_weight"
                    ] * (1 - risk_score),
                    3
                )
        }