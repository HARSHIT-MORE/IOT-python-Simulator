class BaseDevice:

    def __init__(
        self,
        device_id,
        device_type,
        cpu,
        ram,
        battery,
        bandwidth,
        location,
        normal_time
    ):
        self.device_id = device_id
        self.device_type = device_type

        # Resource capabilities
        self.cpu = cpu
        self.ram = ram
        self.battery = battery
        self.bandwidth = bandwidth

        # Context
        self.location = location
        self.normal_time = normal_time

        # Initial trust
        self.trust_score = 0.95

    def get_resource_profile(self):

        return {
            "cpu": self.cpu,
            "ram": self.ram,
            "battery": self.battery,
            "bandwidth": self.bandwidth
        }

    def get_context_profile(self):

        return {
            "location": self.location,
            "normal_time": self.normal_time
        }