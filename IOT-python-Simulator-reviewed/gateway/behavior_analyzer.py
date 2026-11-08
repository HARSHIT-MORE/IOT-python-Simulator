class BehaviorAnalyzer:

    def __init__(self):
        pass

    def calculate_behavior_score(self, data):
        """
        Calculate behavioral trust score.

        Score range:
            0.0 -> Completely abnormal
            1.0 -> Completely normal

        The score is based on observed device behavior.
        """

        # Start with a completely normal behavior score
        score = 1.0

        # ------------------------------------------------------
        # 1. Malicious activity
        # ------------------------------------------------------

        if data.get("malicious_activity", False):

            score -= 0.40

        # ------------------------------------------------------
        # 2. Unexpected network communication
        # ------------------------------------------------------

        if data.get("unexpected_network", False):

            score -= 0.20

        # ------------------------------------------------------
        # 3. Unauthorized command
        # ------------------------------------------------------

        if data.get("unauthorized_command", False):

            score -= 0.25

        # ------------------------------------------------------
        # 4. Explicit malicious status
        # ------------------------------------------------------

        if data.get("status") == "malicious":

            score -= 0.15

        # ------------------------------------------------------
        # Keep score between 0 and 1
        # ------------------------------------------------------

        score = max(0.0, min(1.0, score))

        return round(score, 3)

    def get_behavior_status(self, behavior_score):

        if behavior_score >= 0.80:

            return "NORMAL"

        elif behavior_score >= 0.60:

            return "SLIGHTLY_ABNORMAL"

        elif behavior_score >= 0.40:

            return "SUSPICIOUS"

        else:

            return "HIGHLY_ABNORMAL"

    def analyze(self, data):

        behavior_score = (
            self.calculate_behavior_score(data)
        )

        behavior_status = (
            self.get_behavior_status(
                behavior_score
            )
        )

        return {
            "behavior_score": behavior_score,
            "behavior_status": behavior_status
        }