class ResourceManager:

    def __init__(self):
        pass

    # ==========================================================
    # RESOURCE CAPABILITY
    # ==========================================================

    def calculate_rcf(self, device):
        """
        Calculate Resource Capability Factor (RCF).

        RCF represents the capability of the device,
        not its current workload.
        """

        cpu = device.cpu
        ram = device.ram
        battery = device.battery
        bandwidth = device.bandwidth

        # Equal weights for initial model
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

    # ==========================================================
    # RESOURCE LEVEL
    # ==========================================================

    def get_resource_level(self, rcf):

        if rcf < 0.3:
            return "VERY_CONSTRAINED"

        elif rcf < 0.6:
            return "MODERATE"

        elif rcf < 0.8:
            return "CAPABLE"

        else:
            return "HIGHLY_CAPABLE"

    # ==========================================================
    # SECURITY LEVEL BASED ON CAPABILITY
    # ==========================================================

    def get_security_level(self, rcf):

        if rcf < 0.3:
            return "LIGHTWEIGHT"

        elif rcf < 0.6:
            return "LIGHTWEIGHT_WITH_PERIODIC_VERIFICATION"

        elif rcf < 0.8:
            return "STRONG_VERIFICATION"

        else:
            return "CONTINUOUS_MONITORING"

    # ==========================================================
    # RESOURCE PRESSURE
    # ==========================================================

    def calculate_resource_pressure(self, device):
        """
        Calculate current Resource Pressure (RP).

        RP represents how heavily the device is currently
        utilizing its available resources.

        RP is different from RCF.

        RCF -> capability
        RP  -> current pressure
        """

        cpu_usage = device.cpu_usage
        ram_usage = device.ram_usage
        bandwidth_usage = device.bandwidth_usage

        # Convert battery level into battery pressure.
        #
        # Example:
        # battery = 0.90 -> pressure = 0.10
        # battery = 0.30 -> pressure = 0.70

        battery_pressure = 1 - device.battery_level

        # Equal initial weights
        w_cpu = 0.30
        w_ram = 0.30
        w_battery = 0.20
        w_bandwidth = 0.20

        resource_pressure = (
            w_cpu * cpu_usage
            + w_ram * ram_usage
            + w_battery * battery_pressure
            + w_bandwidth * bandwidth_usage
        )

        return round(resource_pressure, 3)

    # ==========================================================
    # RESOURCE PRESSURE LEVEL
    # ==========================================================

    def get_pressure_level(self, resource_pressure):

        if resource_pressure < 0.3:
            return "LOW"

        elif resource_pressure < 0.6:
            return "MODERATE"

        elif resource_pressure < 0.8:
            return "HIGH"

        else:
            return "CRITICAL"