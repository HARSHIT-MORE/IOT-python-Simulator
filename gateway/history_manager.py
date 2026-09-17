class HistoryManager:

    def __init__(self):

        # ======================================================
        # WEIGHTS
        # ======================================================

        self.success_weight = 0.25
        self.behavior_weight = 0.30
        self.context_weight = 0.20
        self.failure_penalty = 0.10
        self.anomaly_penalty = 0.10
        self.compromise_penalty = 0.05

        # ======================================================
        # HISTORY STORAGE
        # ======================================================

        self.history = {}

    # ==========================================================
    # REGISTER DEVICE
    # ==========================================================

    def register_device(self, device_id):

        if device_id not in self.history:

            self.history[device_id] = {

                "behavior_scores": [],

                "context_scores": [],

                "successes": 0,

                "failures": 0,

                "anomalies": 0,

                "previous_compromise": False
            }

    # ==========================================================
    # RECORD OBSERVATION
    # ==========================================================

    def record_observation(
        self,
        device_id,
        behavior_score,
        context_score,
        success=True,
        anomaly=False,
        compromised=False
    ):

        # Automatically register unknown device

        if device_id not in self.history:

            self.register_device(
                device_id
            )

        device_history = (
            self.history[device_id]
        )

        # ------------------------------------------------------
        # Store behavior
        # ------------------------------------------------------

        device_history[
            "behavior_scores"
        ].append(
            behavior_score
        )

        # ------------------------------------------------------
        # Store context
        # ------------------------------------------------------

        device_history[
            "context_scores"
        ].append(
            context_score
        )

        # ------------------------------------------------------
        # Success / failure
        # ------------------------------------------------------

        if success:

            device_history[
                "successes"
            ] += 1

        else:

            device_history[
                "failures"
            ] += 1

        # ------------------------------------------------------
        # Anomaly
        # ------------------------------------------------------

        if anomaly:

            device_history[
                "anomalies"
            ] += 1

        # ------------------------------------------------------
        # Previous compromise
        # ------------------------------------------------------

        if compromised:

            device_history[
                "previous_compromise"
            ] = True

    # ==========================================================
    # AVERAGE BEHAVIOR
    # ==========================================================

    def calculate_average_behavior(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return 0.5

        scores = history[
            "behavior_scores"
        ]

        if len(scores) == 0:

            return 0.5

        return sum(scores) / len(scores)

    # ==========================================================
    # AVERAGE CONTEXT
    # ==========================================================

    def calculate_average_context(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return 0.5

        scores = history[
            "context_scores"
        ]

        if len(scores) == 0:

            return 0.5

        return sum(scores) / len(scores)

    # ==========================================================
    # SUCCESS RATE
    # ==========================================================

    def calculate_success_rate(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return 0.5

        successes = history[
            "successes"
        ]

        failures = history[
            "failures"
        ]

        total = successes + failures

        if total == 0:

            return 0.5

        return successes / total

    # ==========================================================
    # FAILURE RATE
    # ==========================================================

    def calculate_failure_rate(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return 0.0

        successes = history[
            "successes"
        ]

        failures = history[
            "failures"
        ]

        total = successes + failures

        if total == 0:

            return 0.0

        return failures / total

    # ==========================================================
    # ANOMALY RATE
    # ==========================================================

    def calculate_anomaly_rate(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return 0.0

        anomalies = history[
            "anomalies"
        ]

        total = len(
            history["behavior_scores"]
        )

        if total == 0:

            return 0.0

        return anomalies / total

    # ==========================================================
    # COMPROMISE HISTORY
    # ==========================================================

    def has_previous_compromise(
        self,
        device_id
    ):

        history = self.history.get(
            device_id
        )

        if history is None:

            return False

        return history[
            "previous_compromise"
        ]

    # ==========================================================
    # HISTORICAL TRUST SCORE
    # ==========================================================

    def calculate_history_score(
        self,
        device_id
    ):

        average_behavior = (
            self.calculate_average_behavior(
                device_id
            )
        )

        average_context = (
            self.calculate_average_context(
                device_id
            )
        )

        success_rate = (
            self.calculate_success_rate(
                device_id
            )
        )

        failure_rate = (
            self.calculate_failure_rate(
                device_id
            )
        )

        anomaly_rate = (
            self.calculate_anomaly_rate(
                device_id
            )
        )

        previous_compromise = (
            self.has_previous_compromise(
                device_id
            )
        )

        # ------------------------------------------------------
        # Historical trust
        # ------------------------------------------------------

        history_score = (

            self.success_weight
            * success_rate

            + self.behavior_weight
            * average_behavior

            + self.context_weight
            * average_context

            - self.failure_penalty
            * failure_rate

            - self.anomaly_penalty
            * anomaly_rate
        )

        # ------------------------------------------------------
        # Previous compromise penalty
        # ------------------------------------------------------

        if previous_compromise:

            history_score -= (
                self.compromise_penalty
            )

        # ------------------------------------------------------
        # Keep score between 0 and 1
        # ------------------------------------------------------

        history_score = max(
            0.0,
            min(
                1.0,
                history_score
            )
        )

        return round(
            history_score,
            3
        )

    # ==========================================================
    # HISTORY STATUS
    # ==========================================================

    def get_history_status(
        self,
        history_score
    ):

        if history_score >= 0.80:

            return "GOOD_HISTORY"

        elif history_score >= 0.60:

            return "ACCEPTABLE_HISTORY"

        elif history_score >= 0.40:

            return "QUESTIONABLE_HISTORY"

        else:

            return "POOR_HISTORY"

    # ==========================================================
    # COMPLETE HISTORY ANALYSIS
    # ==========================================================

    def analyze(
        self,
        device_id
    ):

        history_score = (
            self.calculate_history_score(
                device_id
            )
        )

        return {

            "history_score":
                history_score,

            "history_status":
                self.get_history_status(
                    history_score
                ),

            "success_rate":
                round(
                    self.calculate_success_rate(
                        device_id
                    ),
                    3
                ),

            "failure_rate":
                round(
                    self.calculate_failure_rate(
                        device_id
                    ),
                    3
                ),

            "anomaly_rate":
                round(
                    self.calculate_anomaly_rate(
                        device_id
                    ),
                    3
                ),

            "average_behavior":
                round(
                    self.calculate_average_behavior(
                        device_id
                    ),
                    3
                ),

            "average_context":
                round(
                    self.calculate_average_context(
                        device_id
                    ),
                    3
                ),

            "previous_compromise":
                self.has_previous_compromise(
                    device_id
                )
        }