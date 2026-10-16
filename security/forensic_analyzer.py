class ForensicAnalyzer:

    def __init__(self):

        # ========================================================
        # SEVERITY THRESHOLDS
        # ========================================================

        self.severity_thresholds = {
            "LOW": 0.30,
            "MEDIUM": 0.60,
            "HIGH": 0.80
        }

        # ========================================================
        # SEVERITY WEIGHTS
        # ========================================================
        #
        # Risk and trust describe the overall security state.
        #
        # Forensic indicators provide direct evidence of a
        # possible security incident.
        #
        # Total = 1.00
        #

        self.risk_weight = 0.30
        self.trust_weight = 0.20
        self.probability_weight = 0.15
        self.impact_weight = 0.10
        self.evidence_weight = 0.25


    # ============================================================
    # DETERMINE ATTACK TYPE
    # ============================================================

    def determine_attack_type(self, event):

        if event.get("attack_type"):
            return event.get("attack_type")

        if event.get("tampered", False):
            return "MESSAGE_TAMPERING"

        if event.get("malicious_activity", False):
            return "DEVICE_COMPROMISE"

        if event.get("unauthorized_command", False):
            return "UNAUTHORIZED_COMMAND"

        if event.get("unexpected_network", False):
            return "UNEXPECTED_NETWORK_ACTIVITY"

        return "UNKNOWN_SECURITY_EVENT"


    # ============================================================
    # CALCULATE EVIDENCE STRENGTH
    # ============================================================

    def calculate_evidence_strength(self, event):

        evidence_score = 0.0

        # --------------------------------------------------------
        # Direct security indicators
        # --------------------------------------------------------

        if event.get("malicious_activity", False):
            evidence_score += 0.30

        if event.get("unexpected_network", False):
            evidence_score += 0.20

        if event.get("unauthorized_command", False):
            evidence_score += 0.25

        if event.get("tampered", False):
            evidence_score += 0.30

        # --------------------------------------------------------
        # Strong behavioral anomaly
        # --------------------------------------------------------

        behavior_score = event.get(
            "behavior_score",
            1.0
        )

        if behavior_score < 0.40:
            evidence_score += 0.20

        # --------------------------------------------------------
        # Strong contextual anomaly
        # --------------------------------------------------------

        context_score = event.get(
            "context_score",
            1.0
        )

        if context_score < 0.40:
            evidence_score += 0.15

        # --------------------------------------------------------
        # Low adaptive trust
        # --------------------------------------------------------

        trust_score = event.get(
            "adaptive_trust_score",
            1.0
        )

        if trust_score < 0.40:
            evidence_score += 0.20

        # --------------------------------------------------------
        # Cap evidence strength
        # --------------------------------------------------------

        return round(
            min(1.0, evidence_score),
            3
        )


    # ============================================================
    # CALCULATE INCIDENT SEVERITY
    # ============================================================

    def calculate_severity(self, event):

        risk_score = event.get(
            "risk_score",
            0.0
        )

        trust_score = event.get(
            "adaptive_trust_score",
            1.0
        )

        probability = event.get(
            "probability_of_compromise",
            0.0
        )

        impact = event.get(
            "impact",
            0.0
        )

        # --------------------------------------------------------
        # Convert trust into distrust
        # --------------------------------------------------------

        distrust_score = 1.0 - trust_score

        # --------------------------------------------------------
        # Calculate direct forensic evidence strength
        # --------------------------------------------------------

        evidence_strength = (
            self.calculate_evidence_strength(event)
        )

        # --------------------------------------------------------
        # Severity model
        # --------------------------------------------------------
        #
        # Severity considers:
        #
        # 1. Overall security risk
        # 2. Lack of trust
        # 3. Probability of compromise
        # 4. Potential impact
        # 5. Direct forensic evidence
        #

        severity_score = (
            self.risk_weight * risk_score
            + self.trust_weight * distrust_score
            + self.probability_weight * probability
            + self.impact_weight * impact
            + self.evidence_weight * evidence_strength
        )

        severity_score = max(
            0.0,
            min(1.0, severity_score)
        )

        # --------------------------------------------------------
        # Determine severity category
        # --------------------------------------------------------

        if severity_score >= self.severity_thresholds["HIGH"]:

            severity = "HIGH"

        elif severity_score >= self.severity_thresholds["MEDIUM"]:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        return {
            "severity_score": round(
                severity_score,
                3
            ),

            "severity": severity,

            "evidence_strength": round(
                evidence_strength,
                3
            )
        }


    # ============================================================
    # IDENTIFY INDICATORS OF COMPROMISE
    # ============================================================

    def identify_indicators(self, event):

        indicators = []

        # --------------------------------------------------------
        # Direct malicious indicators
        # --------------------------------------------------------

        if event.get(
            "malicious_activity",
            False
        ):

            indicators.append(
                "Malicious activity detected"
            )

        if event.get(
            "unexpected_network",
            False
        ):

            indicators.append(
                "Unexpected network activity detected"
            )

        if event.get(
            "unauthorized_command",
            False
        ):

            indicators.append(
                "Unauthorized command detected"
            )

        if event.get(
            "tampered",
            False
        ):

            indicators.append(
                "Message tampering detected"
            )

        # --------------------------------------------------------
        # Behavioral indicators
        # --------------------------------------------------------

        behavior_score = event.get(
            "behavior_score",
            1.0
        )

        if behavior_score < 0.40:

            indicators.append(
                "Highly abnormal behavior"
            )

        elif behavior_score < 0.60:

            indicators.append(
                "Suspicious behavior"
            )

        # --------------------------------------------------------
        # Contextual indicators
        # --------------------------------------------------------

        context_score = event.get(
            "context_score",
            1.0
        )

        if context_score < 0.40:

            indicators.append(
                "Highly abnormal context"
            )

        elif context_score < 0.60:

            indicators.append(
                "Suspicious context"
            )

        # --------------------------------------------------------
        # Risk indicators
        # --------------------------------------------------------

        risk_score = event.get(
            "risk_score",
            0.0
        )

        if risk_score >= 0.80:

            indicators.append(
                "Critical security risk"
            )

        elif risk_score >= 0.60:

            indicators.append(
                "High security risk"
            )

        elif risk_score >= 0.30:

            indicators.append(
                "Elevated security risk"
            )

        # --------------------------------------------------------
        # Trust indicators
        # --------------------------------------------------------

        trust_score = event.get(
            "adaptive_trust_score",
            1.0
        )

        if trust_score < 0.40:

            indicators.append(
                "Very low adaptive trust"
            )

        elif trust_score < 0.60:

            indicators.append(
                "Reduced adaptive trust"
            )

        return indicators


    # ============================================================
    # DETERMINE RECOMMENDED ACTION
    # ============================================================

    def determine_recommended_action(
        self,
        severity,
        attack_type,
        decision,
        security_action
    ):

        # --------------------------------------------------------
        # Highest priority: severe incident
        # --------------------------------------------------------

        if severity == "HIGH":

            return "ISOLATE_AND_INVESTIGATE"

        # --------------------------------------------------------
        # Message tampering
        # --------------------------------------------------------

        if attack_type == "MESSAGE_TAMPERING":

            return "REJECT_MESSAGE_AND_INVESTIGATE"

        # --------------------------------------------------------
        # Explicit denial
        # --------------------------------------------------------

        if decision == "DENY":

            return "BLOCK_AND_MONITOR"

        # --------------------------------------------------------
        # Restricted access
        # --------------------------------------------------------

        if security_action == "LIMIT_ACCESS_AND_MONITOR":

            return "RESTRICT_AND_MONITOR"

        # --------------------------------------------------------
        # Medium severity
        # --------------------------------------------------------

        if severity == "MEDIUM":

            return "MONITOR_AND_COLLECT_MORE_EVIDENCE"

        # --------------------------------------------------------
        # Default
        # --------------------------------------------------------

        return "CONTINUE_MONITORING"


    # ============================================================
    # ANALYZE FORENSIC EVIDENCE
    # ============================================================

    def analyze(self, evidence):

        event = evidence.get(
            "event",
            {}
        )

        device_id = evidence.get(
            "device_id",
            "UNKNOWN"
        )

        # --------------------------------------------------------
        # Trust score
        # --------------------------------------------------------

        trust_score = evidence.get(
            "trust_score",
            event.get(
                "adaptive_trust_score",
                0.0
            )
        )

        # --------------------------------------------------------
        # Attack type
        # --------------------------------------------------------

        attack_type = self.determine_attack_type(
            event
        )

        # --------------------------------------------------------
        # Severity
        # --------------------------------------------------------

        severity_analysis = self.calculate_severity(
            event
        )

        # --------------------------------------------------------
        # Indicators
        # --------------------------------------------------------

        indicators = self.identify_indicators(
            event
        )

        # --------------------------------------------------------
        # Decision information
        # --------------------------------------------------------

        decision = event.get(
            "decision",
            "UNKNOWN"
        )

        security_action = event.get(
            "security_action",
            "UNKNOWN"
        )

        # --------------------------------------------------------
        # Recommended action
        # --------------------------------------------------------

        recommended_action = (
            self.determine_recommended_action(
                severity_analysis["severity"],
                attack_type,
                decision,
                security_action
            )
        )

        # --------------------------------------------------------
        # Final forensic result
        # --------------------------------------------------------

        forensic_result = {

            "device_id":
                device_id,

            "attack_type":
                attack_type,

            "severity":
                severity_analysis["severity"],

            "severity_score":
                severity_analysis["severity_score"],

            "evidence_strength":
                severity_analysis["evidence_strength"],

            "trust_score":
                round(
                    trust_score,
                    3
                ),

            "risk_score":
                round(
                    event.get(
                        "risk_score",
                        0.0
                    ),
                    3
                ),

            "probability_of_compromise":
                round(
                    event.get(
                        "probability_of_compromise",
                        0.0
                    ),
                    3
                ),

            "impact":
                round(
                    event.get(
                        "impact",
                        0.0
                    ),
                    3
                ),

            "decision":
                decision,

            "security_action":
                security_action,

            "indicators_of_compromise":
                indicators,

            "recommended_action":
                recommended_action
        }

        return forensic_result


    # ============================================================
    # DISPLAY FORENSIC ANALYSIS
    # ============================================================

    def display_analysis(
        self,
        forensic_result
    ):

        print(
            "\n"
            + "=" * 70
        )

        print(
            "[FORENSIC ANALYSIS]"
        )

        print(
            "=" * 70
        )

        print(
            "Device                  :",
            forensic_result["device_id"]
        )

        print(
            "Attack Type             :",
            forensic_result["attack_type"]
        )

        print(
            "Trust Score             :",
            forensic_result["trust_score"]
        )

        print(
            "Risk Score              :",
            forensic_result["risk_score"]
        )

        print(
            "Probability of Compromise:",
            forensic_result[
                "probability_of_compromise"
            ]
        )

        print(
            "Impact                  :",
            forensic_result["impact"]
        )

        print(
            "Evidence Strength       :",
            forensic_result["evidence_strength"]
        )

        print(
            "Incident Severity       :",
            forensic_result["severity"]
        )

        print(
            "Severity Score          :",
            forensic_result["severity_score"]
        )

        print(
            "Decision                :",
            forensic_result["decision"]
        )

        print(
            "Security Action         :",
            forensic_result["security_action"]
        )

        print(
            "\nIndicators of Compromise:"
        )

        if len(
            forensic_result[
                "indicators_of_compromise"
            ]
        ) == 0:

            print(
                "  - No strong indicators identified"
            )

        else:

            for indicator in (
                forensic_result[
                    "indicators_of_compromise"
                ]
            ):

                print(
                    "  -",
                    indicator
                )

        print(
            "\nRecommended Action      :",
            forensic_result[
                "recommended_action"
            ]
        )

        print(
            "=" * 70
        )