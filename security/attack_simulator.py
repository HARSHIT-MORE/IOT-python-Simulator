class AttackSimulator:

    def __init__(self):

        self.attacked_devices = set()

    def compromise_device(self, device_id):

        self.attacked_devices.add(device_id)

        print(
            f"\n[ATTACK SIMULATOR] "
            f"{device_id} has been compromised!"
        )

    def is_compromised(self, device_id):

        return device_id in self.attacked_devices

    def generate_malicious_data(self, data):

        device_id = data["device_id"]

        if self.is_compromised(device_id):

            data["status"] = "malicious"

            data["malicious_activity"] = True

            data["unexpected_network"] = True

            data["unauthorized_command"] = True

        return data