import time

from devices.smart_clock import SmartClock
from devices.temperature_sensor import TemperatureSensor
from devices.motion_sensor import MotionSensor
from devices.camera import Camera

from edge.raspberry_pi import RaspberryPi

from gateway.gateway import Gateway
from gateway.trust_manager import TrustManager
from gateway.resource_manager import ResourceManager

from security.attack_simulator import AttackSimulator
from security.evidence_collector import EvidenceCollector


def main():

    print("=" * 70)
    print("              SMART IoT SECURITY SIMULATOR")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. CREATE IoT DEVICES
    # ---------------------------------------------------------

    clock = SmartClock("CLOCK_001")

    temperature = TemperatureSensor("TEMP_001")

    motion = MotionSensor("MOTION_001")

    camera = Camera("CAM_001")


    # ---------------------------------------------------------
    # 2. CREATE RASPBERRY PI
    # ---------------------------------------------------------

    raspberry_pi = RaspberryPi()


    # ---------------------------------------------------------
    # 3. CREATE TRUST MANAGER
    # ---------------------------------------------------------

    trust_manager = TrustManager()

    trust_manager.register_device("CLOCK_001")

    trust_manager.register_device("TEMP_001")

    trust_manager.register_device("MOTION_001")

    trust_manager.register_device("CAM_001")


    # ---------------------------------------------------------
    # 4. CREATE EVIDENCE COLLECTOR
    # ---------------------------------------------------------

    evidence_collector = EvidenceCollector()


    # ---------------------------------------------------------
    # 5. CREATE GATEWAY
    # ---------------------------------------------------------

    gateway = Gateway(
        trust_manager,
        evidence_collector
    )


    # ---------------------------------------------------------
    # 6. CREATE RESOURCE MANAGER
    # ---------------------------------------------------------

    resource_manager = ResourceManager()


    # ---------------------------------------------------------
    # 7. CREATE ATTACK SIMULATOR
    # ---------------------------------------------------------

    attack_simulator = AttackSimulator()


    # ---------------------------------------------------------
    # 8. STORE ALL DEVICES IN A LIST
    # ---------------------------------------------------------

    devices = [
        clock,
        temperature,
        motion,
        camera
    ]


    # ---------------------------------------------------------
    # 9. DISPLAY DEVICE RESOURCE PROFILES
    # ---------------------------------------------------------

    print("\nDEVICE RESOURCE PROFILES")
    print("-" * 70)

    for device in devices:

        rcf = resource_manager.calculate_rcf(device)

        resource_level = (
            resource_manager.get_resource_level(rcf)
        )

        security_level = (
            resource_manager.get_security_level(rcf)
        )

        print(
            f"{device.device_id:15} "
            f"RCF = {rcf:.3f} | "
            f"Resource = {resource_level:18} | "
            f"Security = {security_level}"
        )


    # ---------------------------------------------------------
    # 10. RUN SIMULATION
    # ---------------------------------------------------------

    for iteration in range(1, 16):

        print("\n")
        print("=" * 70)
        print(f"                    SIMULATION ROUND {iteration}")
        print("=" * 70)


        # -----------------------------------------------------
        # 11. SIMULATE ATTACK
        # -----------------------------------------------------

        if iteration == 6:

            attack_simulator.compromise_device(
                "MOTION_001"
            )


        # -----------------------------------------------------
        # 12. GENERATE DATA FROM EACH DEVICE
        # -----------------------------------------------------

        for device in devices:

            data = device.generate_data()


            # -------------------------------------------------
            # 13. APPLY ATTACK SIMULATION
            # -------------------------------------------------

            data = attack_simulator.generate_malicious_data(
                data
            )


            # -------------------------------------------------
            # 14. SEND DATA TO RASPBERRY PI
            # -------------------------------------------------

            raspberry_pi.receive_data(data)


        # -----------------------------------------------------
        # 15. RASPBERRY PI SENDS DATA TO GATEWAY
        # -----------------------------------------------------

        while len(raspberry_pi.device_data) > 0:

            raspberry_pi.send_to_gateway(
                gateway
            )


        # -----------------------------------------------------
        # 16. DISPLAY CURRENT TRUST
        # -----------------------------------------------------

        print("\nCURRENT DEVICE TRUST")
        print("-" * 70)

        for device_id in trust_manager.trust_scores:

            score = trust_manager.get_trust_score(
                device_id
            )

            status = trust_manager.get_status(
                device_id
            )

            print(
                f"{device_id:15} "
                f"Trust = {score:.2f} "
                f"Status = {status}"
            )


        # -----------------------------------------------------
        # 17. DISPLAY CURRENT RESOURCE INFORMATION
        # -----------------------------------------------------

        print("\nCURRENT RESOURCE INFORMATION")
        print("-" * 70)

        for device in devices:

            rcf = resource_manager.calculate_rcf(
                device
            )

            resource_level = (
                resource_manager.get_resource_level(
                    rcf
                )
            )

            print(
                f"{device.device_id:15} "
                f"RCF = {rcf:.3f} "
                f"Level = {resource_level}"
            )


        # -----------------------------------------------------
        # 18. WAIT BEFORE NEXT ROUND
        # -----------------------------------------------------

        time.sleep(2)


# -------------------------------------------------------------
# PROGRAM ENTRY POINT
# -------------------------------------------------------------

if __name__ == "__main__":

    main()