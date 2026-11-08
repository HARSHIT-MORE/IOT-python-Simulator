class SecurityMetrics:

    def __init__(self):

        self.records = []

    # ========================================================
    # RECORD ONE OBSERVATION
    # ========================================================

    def add_record(
        self,
        device_id,
        round_number,
        ground_truth_attack,
        detected_attack,
        decision,
        trust_score,
        risk_score,
        behavior_score,
        context_score
    ):

        self.records.append({

            "device_id":
                device_id,

            "round":
                round_number,

            "ground_truth_attack":
                bool(
                    ground_truth_attack
                ),

            "detected_attack":
                bool(
                    detected_attack
                ),

            "decision":
                decision,

            "trust_score":
                trust_score,

            "risk_score":
                risk_score,

            "behavior_score":
                behavior_score,

            "context_score":
                context_score
        })

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    def confusion_matrix(
        self
    ):

        tp = 0
        tn = 0
        fp = 0
        fn = 0

        for record in self.records:

            actual = record[
                "ground_truth_attack"
            ]

            detected = record[
                "detected_attack"
            ]

            if actual and detected:

                tp += 1

            elif not actual and not detected:

                tn += 1

            elif not actual and detected:

                fp += 1

            elif actual and not detected:

                fn += 1

        return {

            "TP":
                tp,

            "TN":
                tn,

            "FP":
                fp,

            "FN":
                fn
        }

    # ========================================================
    # DETECTION RATE
    # ========================================================

    def detection_rate(
        self
    ):

        cm = self.confusion_matrix()

        tp = cm["TP"]

        fn = cm["FN"]

        denominator = (
            tp + fn
        )

        if denominator == 0:

            return 0.0

        return (
            tp
            /
            denominator
        )

    # ========================================================
    # PRECISION
    # ========================================================

    def precision(
        self
    ):

        cm = self.confusion_matrix()

        tp = cm["TP"]

        fp = cm["FP"]

        denominator = (
            tp + fp
        )

        if denominator == 0:

            return 0.0

        return (
            tp
            /
            denominator
        )

    # ========================================================
    # RECALL
    # ========================================================

    def recall(
        self
    ):

        return self.detection_rate()

    # ========================================================
    # F1 SCORE
    # ========================================================

    def f1_score(
        self
    ):

        precision = self.precision()

        recall = self.recall()

        denominator = (
            precision
            +
            recall
        )

        if denominator == 0:

            return 0.0

        return (
            2
            *
            precision
            *
            recall
            /
            denominator
        )

    # ========================================================
    # FALSE POSITIVE RATE
    # ========================================================

    def false_positive_rate(
        self
    ):

        cm = self.confusion_matrix()

        fp = cm["FP"]

        tn = cm["TN"]

        denominator = (
            fp + tn
        )

        if denominator == 0:

            return 0.0

        return (
            fp
            /
            denominator
        )

    # ========================================================
    # FALSE NEGATIVE RATE
    # ========================================================

    def false_negative_rate(
        self
    ):

        cm = self.confusion_matrix()

        fn = cm["FN"]

        tp = cm["TP"]

        denominator = (
            fn + tp
        )

        if denominator == 0:

            return 0.0

        return (
            fn
            /
            denominator
        )

    # ========================================================
    # ACCURACY
    # ========================================================

    def accuracy(
        self
    ):

        cm = self.confusion_matrix()

        tp = cm["TP"]

        tn = cm["TN"]

        fp = cm["FP"]

        fn = cm["FN"]

        total = (
            tp
            +
            tn
            +
            fp
            +
            fn
        )

        if total == 0:

            return 0.0

        return (
            tp + tn
        ) / total

    # ========================================================
    # DETECTION LATENCY
    # ========================================================

    def detection_latency(
        self
    ):

        attack_records = {}

        for record in self.records:

            if record[
                "ground_truth_attack"
            ]:

                device_id = record[
                    "device_id"
                ]

                if device_id not in attack_records:

                    attack_records[
                        device_id
                    ] = {

                        "attack_round":
                            record[
                                "round"
                            ],

                        "detection_round":
                            None
                    }

                if (
                    record[
                        "detected_attack"
                    ]

                    and

                    attack_records[
                        device_id
                    ][
                        "detection_round"
                    ] is None
                ):

                    attack_records[
                        device_id
                    ][
                        "detection_round"
                    ] = record[
                        "round"
                    ]

        latencies = []

        for device_id, info in (
            attack_records.items()
        ):

            detection_round = info[
                "detection_round"
            ]

            if detection_round is not None:

                latency = (
                    detection_round
                    -
                    info[
                        "attack_round"
                    ]
                )

                latencies.append(
                    latency
                )

        if len(latencies) == 0:

            return None

        return (
            sum(latencies)
            /
            len(latencies)
        )

    # ========================================================
    # COMPLETE METRICS
    # ========================================================

    def calculate_all(
        self
    ):

        cm = self.confusion_matrix()

        return {

            "accuracy":
                round(
                    self.accuracy(),
                    4
                ),

            "detection_rate":
                round(
                    self.detection_rate(),
                    4
                ),

            "precision":
                round(
                    self.precision(),
                    4
                ),

            "recall":
                round(
                    self.recall(),
                    4
                ),

            "f1_score":
                round(
                    self.f1_score(),
                    4
                ),

            "false_positive_rate":
                round(
                    self.false_positive_rate(),
                    4
                ),

            "false_negative_rate":
                round(
                    self.false_negative_rate(),
                    4
                ),

            "detection_latency":
                self.detection_latency(),

            "TP":
                cm["TP"],

            "TN":
                cm["TN"],

            "FP":
                cm["FP"],

            "FN":
                cm["FN"]
        }

    # ========================================================
    # DISPLAY METRICS
    # ========================================================

    def display_metrics(
        self
    ):

        results = self.calculate_all()

        print("\n")

        print("=" * 70)

        print(
            "             SECURITY EVALUATION METRICS"
        )

        print("=" * 70)

        print(
            "Accuracy            :",
            results["accuracy"]
        )

        print(
            "Detection Rate      :",
            results["detection_rate"]
        )

        print(
            "Precision           :",
            results["precision"]
        )

        print(
            "Recall              :",
            results["recall"]
        )

        print(
            "F1 Score            :",
            results["f1_score"]
        )

        print(
            "False Positive Rate :",
            results[
                "false_positive_rate"
            ]
        )

        print(
            "False Negative Rate :",
            results[
                "false_negative_rate"
            ]
        )

        print(
            "Detection Latency   :",
            results[
                "detection_latency"
            ]
        )

        print("\n")

        print(
            "Confusion Matrix"
        )

        print(
            "True Positive       :",
            results["TP"]
        )

        print(
            "True Negative       :",
            results["TN"]
        )

        print(
            "False Positive      :",
            results["FP"]
        )

        print(
            "False Negative      :",
            results["FN"]
        )

        print("=" * 70)