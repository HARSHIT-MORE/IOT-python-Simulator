class ResourceManager:

    def __init__(self):
        pass

    def calculate_rcf(self, device):
        """
        Calculate Resource Capability Factor (RCF).

        All resource values are expected to be
        normalized between 0 and 1.
        """

        cpu = device.cpu
        ram = device.ram
        battery = device.battery
        bandwidth = device.bandwidth

        # Equal weights for the initial model
        w_cpu = 0.25
        w_ram = 0.25
        w_battery = 0.25
        w_bandwidth = 0.25

        rcf = (
            w_cpu * cpu
            + w_ram * ram
            + w_battery * battery
            + w_bandwidth * bandwidth
        )

        return round(rcf, 3)

    def get_resource_level(self, rcf):

        if rcf < 0.3:
            return "VERY_CONSTRAINED"

        elif rcf < 0.6:
            return "MODERATE"

        elif rcf < 0.8:
            return "CAPABLE"

        else:
            return "HIGHLY_CAPABLE"

    def get_security_level(self, rcf):

        if rcf < 0.3:
            return "LIGHTWEIGHT"

        elif rcf < 0.6:
            return "LIGHTWEIGHT_WITH_PERIODIC_VERIFICATION"

        elif rcf < 0.8:
            return "STRONG_VERIFICATION"

        else:
            return "CONTINUOUS_MONITORING"