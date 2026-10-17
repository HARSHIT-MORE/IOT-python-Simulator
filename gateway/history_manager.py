class HistoryManager:

    def __init__(self):

        # ============================================================
        # HISTORY WEIGHTS
        # ============================================================

        self.success_weight = 0.30
        self.behavior_weight = 0.35
        self.context_weight = 0.35

        # Negative factors
        self.failure_penalty = 0.10
        self.anomaly_penalty = 0.10

        # Forensic penalties
        self.forensic_incident_penalty = 0.10
        self.high_severity_penalty = 0.10

        # ============================================================
        # DEVICE HISTORY
        # ============================================================

        self.history = {}

        # ------------------------------------------------------------
        # IMPORTANT:
        # Stores currently active forensic incidents.
        #
        # Example:
        # {
        #     "MOTION_001": {"DEVICE_COMPROMISE"},
        #     "CAMERA_001": {"MESSAGE_TAMPERING"}
        # }
        #
        # This prevents the same ongoing attack from being counted
        # as a new incident every round.
        # ------------------------------------------------------------

        self.active_incidents = {}

    # ================================================================
    # DEVICE REGISTRATION
    # ================================================================

    def register_device(self, device_id):

        if device_id not in self.history:

            self.history[device_id] = {

                "behavior_scores": [],
                "context_scores": [],

                "successes": 0,
                "failures": 0,
                "anomalies": 0,

                "forensic_incidents": 0,
                "confirmed_incidents": 0,

                "last_attack_type": None,
                "last_severity": None,
                "last_severity_score": 0.0
            }

        if device_id not in self.active_incidents:
            self.active_incidents[device_id] = set()

    # ================================================================
    # RECORD NORMAL OBSERVATION
    # ================================================================

    def record_observation(
        self,
        device_id,
        behavior_score,
        context_score,
        success=True,
        anomaly=False
    ):

        if device_id not in self.history:
            self.register_device(device_id)

        device_history = self.history[device_id]

        # Store behavior and context
        device_history["behavior_scores"].append(
            behavior_score
        )

        device_history["context_scores"].append(
            context_score
        )

        # ------------------------------------------------------------
        # Success / Failure
        # ------------------------------------------------------------

        if success:
            device_history["successes"] += 1
        else:
            device_history["failures"] += 1

        # ------------------------------------------------------------
        # Anomaly
        # ------------------------------------------------------------

        if anomaly:
            device_history["anomalies"] += 1

    # ================================================================
    # RECORD FORENSIC INCIDENT
    # ================================================================

    def record_forensic_incident(
        self,
        device_id,
        forensic_result
    ):

        if device_id not in self.history:
            self.register_device(device_id)

        device_history = self.history[device_id]

        # ------------------------------------------------------------
        # Extract forensic information
        # ------------------------------------------------------------

        severity = forensic_result.get(
            "severity",
            "UNKNOWN"
        )

        attack_type = forensic_result.get(
            "attack_type",
            "UNKNOWN"
        )

        severity_score = forensic_result.get(
            "severity_score",
            0.0
        )

        indicators = forensic_result.get(
            "indicators_of_compromise",
            []
        )

        # ------------------------------------------------------------
        # Check whether this attack is already active
        # ------------------------------------------------------------

        active_incidents = self.active_incidents[device_id]

        is_new_incident = attack_type not in active_incidents

        # ============================================================
        # NEW INCIDENT
        # ============================================================

        if is_new_incident:

            # Mark this attack as active
            active_incidents.add(attack_type)

            # Count the incident only once
            device_history["forensic_incidents"] += 1

            # --------------------------------------------------------
            # Severity and the presence of indicators describe seriousness,
            # not certainty. Count as confirmed only when the forensic pipeline
            # explicitly marks an attack as confirmed.
            # --------------------------------------------------------

            if forensic_result.get("confirmed_attack", False):
                device_history["confirmed_incidents"] += 1

        # ============================================================
        # EXISTING INCIDENT
        # ============================================================

        else:

            # --------------------------------------------------------
            # Do NOT increment forensic_incidents.
            #
            # This is simply another forensic observation of the
            # same ongoing incident.
            # --------------------------------------------------------

            pass

        # ------------------------------------------------------------
        # Always update the latest forensic information
        # ------------------------------------------------------------

        device_history["last_attack_type"] = attack_type
        device_history["last_severity"] = severity
        device_history["last_severity_score"] = severity_score

        return {
            "device_id": device_id,

            "forensic_incidents":
                device_history["forensic_incidents"],

            "confirmed_incidents":
                device_history["confirmed_incidents"],

            "last_attack_type":
                attack_type,

            "last_severity":
                severity,

            "last_severity_score":
                severity_score,

            "new_incident":
                is_new_incident,

            "incident_already_active":
                not is_new_incident
        }

    # ================================================================
    # RESOLVE FORENSIC INCIDENT
    # ================================================================

    def resolve_forensic_incident(
        self,
        device_id,
        attack_type=None
    ):

        if device_id not in self.active_incidents:
            return False

        # ------------------------------------------------------------
        # If attack type is specified, resolve only that incident.
        # ------------------------------------------------------------

        if attack_type is not None:

            if attack_type in self.active_incidents[device_id]:

                self.active_incidents[device_id].remove(
                    attack_type
                )

                return True

            return False

        # ------------------------------------------------------------
        # If no attack type is provided, resolve all active incidents
        # for this device.
        # ------------------------------------------------------------

        self.active_incidents[device_id].clear()

        return True

    # ================================================================
    # CHECK WHETHER DEVICE HAS FORENSIC HISTORY
    # ================================================================

    def has_forensic_incident(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return False

        return history["confirmed_incidents"] > 0

    # ================================================================
    # CHECK WHETHER INCIDENT IS CURRENTLY ACTIVE
    # ================================================================

    def has_active_forensic_incident(
        self,
        device_id,
        attack_type=None
    ):

        if device_id not in self.active_incidents:
            return False

        if attack_type is None:
            return len(
                self.active_incidents[device_id]
            ) > 0

        return attack_type in self.active_incidents[device_id]

    # ================================================================
    # AVERAGE BEHAVIOR
    # ================================================================

    def calculate_average_behavior(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.5

        scores = history["behavior_scores"]

        if len(scores) == 0:
            return 0.5

        return sum(scores) / len(scores)

    # ================================================================
    # AVERAGE CONTEXT
    # ================================================================

    def calculate_average_context(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.5

        scores = history["context_scores"]

        if len(scores) == 0:
            return 0.5

        return sum(scores) / len(scores)

    # ================================================================
    # SUCCESS RATE
    # ================================================================

    def calculate_success_rate(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.5

        successes = history["successes"]
        failures = history["failures"]

        total = successes + failures

        if total == 0:
            return 0.5

        return successes / total

    # ================================================================
    # FAILURE RATE
    # ================================================================

    def calculate_failure_rate(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.0

        successes = history["successes"]
        failures = history["failures"]

        total = successes + failures

        if total == 0:
            return 0.0

        return failures / total

    # ================================================================
    # ANOMALY RATE
    # ================================================================

    def calculate_anomaly_rate(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.0

        anomalies = history["anomalies"]

        total = len(
            history["behavior_scores"]
        )

        if total == 0:
            return 0.0

        return anomalies / total

    # ================================================================
    # FORENSIC PENALTY
    # ================================================================

    def calculate_forensic_penalty(self, device_id):

        history = self.history.get(device_id)

        if history is None:
            return 0.0

        confirmed_incidents = history[
            "confirmed_incidents"
        ]

        last_severity = history[
            "last_severity"
        ]

        # ------------------------------------------------------------
        # Each confirmed incident contributes a penalty.
        # Maximum base penalty = 0.30
        # ------------------------------------------------------------

        penalty = min(
            0.30,
            confirmed_incidents *
            self.forensic_incident_penalty
        )

        # ------------------------------------------------------------
        # Additional penalty for HIGH severity
        # ------------------------------------------------------------

        if last_severity == "HIGH":
            penalty += self.high_severity_penalty

        return min(
            0.40,
            penalty
        )

    # ================================================================
    # HISTORY SCORE
    # ================================================================

    def calculate_history_score(self, device_id):

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

        forensic_penalty = (
            self.calculate_forensic_penalty(
                device_id
            )
        )

        # ------------------------------------------------------------
        # Positive history
        # ------------------------------------------------------------

        positive_score = (

            self.success_weight *
            success_rate

            +

            self.behavior_weight *
            average_behavior

            +

            self.context_weight *
            average_context
        )

        # ------------------------------------------------------------
        # Negative history
        # ------------------------------------------------------------

        negative_score = (

            self.failure_penalty *
            failure_rate

            +

            self.anomaly_penalty *
            anomaly_rate

            +

            forensic_penalty
        )

        # ------------------------------------------------------------
        # Final history score
        # ------------------------------------------------------------

        history_score = (
            positive_score -
            negative_score
        )

        history_score = max(
            0.0,
            min(1.0, history_score)
        )

        return round(
            history_score,
            3
        )

    # ================================================================
    # HISTORY STATUS
    # ================================================================

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

    # ================================================================
    # COMPLETE HISTORY ANALYSIS
    # ================================================================

    def analyze(self, device_id):

        history_score = (
            self.calculate_history_score(
                device_id
            )
        )

        history = self.history.get(
            device_id,
            {}
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

            "forensic_incidents":
                history.get(
                    "forensic_incidents",
                    0
                ),

            "confirmed_incidents":
                history.get(
                    "confirmed_incidents",
                    0
                ),

            "last_attack_type":
                history.get(
                    "last_attack_type"
                ),

            "last_severity":
                history.get(
                    "last_severity"
                ),

            "last_severity_score":
                round(
                    history.get(
                        "last_severity_score",
                        0.0
                    ),
                    3
                ),

            "forensic_incident":
                self.has_forensic_incident(
                    device_id
                ),

            "active_forensic_incidents":
                list(
                    self.active_incidents.get(
                        device_id,
                        set()
                    )
                )
        }