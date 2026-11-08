import random


class AttackSimulator:

    def __init__(self):

        # ====================================================
        # DEVICES THAT ARE COMPROMISED
        # ====================================================

        self.attacked_devices = set()


        # ====================================================
        # DEVICES/ATTACKS USED FOR MESSAGE TAMPERING
        # ====================================================

        self.tampered_devices = set()


        # ====================================================
        # ATTACK HISTORY
        # ====================================================

        self.attack_history = []


    # ========================================================
    # COMPROMISE DEVICE
    # ========================================================

    def compromise_device(
        self,
        device_id
    ):

        self.attacked_devices.add(
            device_id
        )


        self.attack_history.append({

            "device_id":
                device_id,

            "attack_type":
                "DEVICE_COMPROMISE",

            "description":
                "Device has been compromised and may behave maliciously."

        })


        print(
            f"\n[ATTACK SIMULATOR] "
            f"{device_id} has been compromised!"
        )


    # ========================================================
    # CHECK WHETHER DEVICE IS COMPROMISED
    # ========================================================

    def is_compromised(
        self,
        device_id
    ):

        return (
            device_id
            in self.attacked_devices
        )


    # ========================================================
    # GENERATE MALICIOUS DEVICE BEHAVIOR
    # ========================================================

    def generate_malicious_data(
        self,
        data
    ):

        device_id = data[
            "device_id"
        ]


        # ----------------------------------------------------
        # Only compromised devices generate malicious behavior
        # ----------------------------------------------------

        if not self.is_compromised(
            device_id
        ):

            return data


        # ====================================================
        # MALICIOUS BEHAVIOR
        # ====================================================

        data["status"] = (
            "malicious"
        )

        data["malicious_activity"] = (
            True
        )

        data["unexpected_network"] = (
            True
        )

        data["unauthorized_command"] = (
            True
        )


        # ====================================================
        # ADD MALICIOUS ACTIVITY DETAILS
        # ====================================================

        data["attack_type"] = (
            "DEVICE_COMPROMISE"
        )

        data["attack_description"] = (
            "Compromised device generated abnormal behavior."
        )


        return data


    # ========================================================
    # TAMPER MESSAGE
    # ========================================================

    def tamper_message(
        self,
        data
    ):

        device_id = data[
            "device_id"
        ]


        # ====================================================
        # MODIFY MESSAGE AFTER HMAC GENERATION
        # ====================================================

        data["tampered"] = (
            True
        )

        data["attack_type"] = (
            "MESSAGE_TAMPERING"
        )

        data["attack_description"] = (
            "Message modified after authentication."
        )


        # ----------------------------------------------------
        # Modify a data field.
        #
        # Since the HMAC was generated before this modification,
        # Gateway should detect the change.
        # ----------------------------------------------------

        if "temperature" in data:

            original_temperature = (
                data["temperature"]
            )

            data["temperature"] = (
                round(
                    original_temperature
                    + random.uniform(
                        10,
                        30
                    ),
                    2
                )
            )


        elif "motion" in data:

            data["motion"] = (
                "detected"
            )


        elif "event" in data:

            data["event"] = (
                "person_detected"
            )


        else:

            data["unauthorized_command"] = (
                True
            )


        self.tampered_devices.add(
            device_id
        )


        self.attack_history.append({

            "device_id":
                device_id,

            "attack_type":
                "MESSAGE_TAMPERING",

            "description":
                "Message modified after HMAC generation."

        })


        print(
            f"[ATTACK SIMULATOR] "
            f"Message from {device_id} has been tampered."
        )


        return data


    # ========================================================
    # CHECK MESSAGE TAMPERING
    # ========================================================

    def is_message_tampered(
        self,
        device_id
    ):

        return (
            device_id
            in self.tampered_devices
        )


    # ========================================================
    # CLEAR TAMPERING STATUS
    # ========================================================

    def clear_tampering_status(
        self,
        device_id
    ):

        if device_id in self.tampered_devices:

            self.tampered_devices.remove(
                device_id
            )


    # ========================================================
    # GET ATTACK HISTORY
    # ========================================================

    def get_attack_history(
        self
    ):

        return self.attack_history


    # ========================================================
    # GET ATTACK STATUS
    # ========================================================

    def get_attack_status(
        self,
        device_id
    ):

        if self.is_compromised(
            device_id
        ):

            return {
                "under_attack": True,
                "attack_type": "DEVICE_COMPROMISE"
            }


        if self.is_message_tampered(
            device_id
        ):

            return {
                "under_attack": True,
                "attack_type": "MESSAGE_TAMPERING"
            }


        return {
            "under_attack": False,
            "attack_type": None
        }