import time


class Gateway:

    def __init__(
        self,
        trust_manager,
        evidence_collector
    ):

        self.trust_manager = trust_manager

        self.evidence_collector = evidence_collector

        self.isolated_devices = set()

    def receive_data(self, data):

        device_id = data["device_id"]

        print(
            f"\n[GATEWAY] Data received from {device_id}"
        )

        # If device is already isolated
        if device_id in self.isolated_devices:

            print(
                f"[GATEWAY] {device_id} is isolated."
            )

            return

        # Check whether malicious behavior exists
        if data.get("malicious_activity", False):

            print(
                f"[GATEWAY] Malicious activity detected "
                f"from {device_id}"
            )

            self.trust_manager.decrease_trust(
                device_id,
                0.25
            )

            trust_score = self.trust_manager.get_trust_score(
                device_id
            )

            status = self.trust_manager.get_status(
                device_id
            )

            print(
                f"[GATEWAY] Trust Score = "
                f"{trust_score:.2f}"
            )

            print(
                f"[GATEWAY] Status = {status}"
            )

            # Collect evidence
            self.evidence_collector.collect(
                device_id,
                "Malicious activity detected",
                trust_score
            )

            # Isolate if compromised
            if status == "COMPROMISED":

                self.isolate_device(device_id)

        else:

            trust_score = self.trust_manager.get_trust_score(
                device_id
            )

            status = self.trust_manager.get_status(
                device_id
            )

            print(
                f"[GATEWAY] Trust Score = "
                f"{trust_score:.2f}"
            )

            print(
                f"[GATEWAY] Status = {status}"
            )

    def isolate_device(self, device_id):

        self.isolated_devices.add(device_id)

        print(
            "\n[GATEWAY] "
            f"🚨 DEVICE {device_id} ISOLATED"
        )

        print(
            "[GATEWAY] Further communication blocked."
        )