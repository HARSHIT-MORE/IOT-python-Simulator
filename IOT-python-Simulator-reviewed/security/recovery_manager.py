import time


class RecoveryManager:

    def __init__(self):

        # Devices currently undergoing recovery
        self.recovery_devices = set()

        # Recovery history for each device
        self.recovery_history = {}

    # ========================================================
    # START RECOVERY
    # ========================================================

    def start_recovery(
        self,
        device_id,
        forensic_result
    ):

        self.recovery_devices.add(
            device_id
        )

        if device_id not in self.recovery_history:

            self.recovery_history[
                device_id
            ] = []

        recovery_event = {

            "device_id":
                device_id,

            "recovery_status":
                "STARTED",

            "forensic_severity":
                forensic_result.get(
                    "severity",
                    "UNKNOWN"
                ),

            "attack_type":
                forensic_result.get(
                    "attack_type",
                    "UNKNOWN"
                ),

            "timestamp":
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        }

        self.recovery_history[
            device_id
        ].append(
            recovery_event
        )

        print(
            f"\n[RECOVERY] Recovery started for {device_id}"
        )

        return recovery_event

    # ========================================================
    # CHECK RECOVERY STATUS
    # ========================================================

    def is_under_recovery(
        self,
        device_id
    ):

        return (
            device_id
            in self.recovery_devices
        )

    # ========================================================
    # RE-AUTHENTICATION
    # ========================================================

    def reauthenticate_device(
        self,
        device_id,
        authentication_result
    ):

        if authentication_result:

            print(
                f"[RECOVERY] Re-authentication successful for {device_id}"
            )

            return True

        print(
            f"[RECOVERY] Re-authentication FAILED for {device_id}"
        )

        return False

    # ========================================================
    # RE-EVALUATE DEVICE
    # ========================================================

    def reevaluate_device(
        self,
        device_id,
        behavior_score,
        context_score,
        risk_score,
        trust_score
    ):

        # ----------------------------------------------------
        # Device is considered safe for recovery when:
        #
        # 1. Behavior is normal
        # 2. Context is normal
        # 3. Risk is low
        # 4. Trust is sufficiently high
        # ----------------------------------------------------

        behavior_normal = (
            behavior_score >= 0.80
        )

        context_normal = (
            context_score >= 0.80
        )

        risk_acceptable = (
            risk_score < 0.30
        )

        trust_acceptable = (
            trust_score >= 0.75
        )

        if (
            behavior_normal
            and
            context_normal
            and
            risk_acceptable
            and
            trust_acceptable
        ):

            status = "RECOVERY_SUCCESSFUL"

        else:

            status = "RECOVERY_FAILED"

        result = {

            "device_id":
                device_id,

            "behavior_score":
                round(
                    behavior_score,
                    3
                ),

            "context_score":
                round(
                    context_score,
                    3
                ),

            "risk_score":
                round(
                    risk_score,
                    3
                ),

            "trust_score":
                round(
                    trust_score,
                    3
                ),

            "behavior_normal":
                behavior_normal,

            "context_normal":
                context_normal,

            "risk_acceptable":
                risk_acceptable,

            "trust_acceptable":
                trust_acceptable,

            "recovery_status":
                status,

            "timestamp":
                time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        }

        return result

    # ========================================================
    # COMPLETE RECOVERY
    # ========================================================

    def complete_recovery(
        self,
        device_id,
        recovery_result
    ):

        if (
            recovery_result[
                "recovery_status"
            ]
            ==
            "RECOVERY_SUCCESSFUL"
        ):

            if device_id in self.recovery_devices:

                self.recovery_devices.remove(
                    device_id
                )

            print(
                f"\n[RECOVERY] {device_id} successfully recovered."
            )

            print(
                "[RECOVERY] Device can return to monitored operation."
            )

        else:

            print(
                f"\n[RECOVERY] Recovery failed for {device_id}."
            )

            print(
                "[RECOVERY] Device remains isolated."
            )

        if device_id not in self.recovery_history:

            self.recovery_history[
                device_id
            ] = []

        self.recovery_history[
            device_id
        ].append(
            recovery_result
        )

        return recovery_result

    # ========================================================
    # GET RECOVERY HISTORY
    # ========================================================

    def get_recovery_history(
        self,
        device_id
    ):

        return self.recovery_history.get(
            device_id,
            []
        )

    # ========================================================
    # GET DEVICES UNDER RECOVERY
    # ========================================================

    def get_devices_under_recovery(self):

        return list(
            self.recovery_devices
        )