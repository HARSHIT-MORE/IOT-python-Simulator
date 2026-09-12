import time

from devices.smart_clock import SmartClock
from devices.temperature_sensor import TemperatureSensor
from devices.motion_sensor import MotionSensor
from devices.camera import Camera

from edge.raspberry_pi import RaspberryPi

from gateway.gateway import Gateway
from gateway.trust_manager import TrustManager

from security.attack_simulator import AttackSimulator
from security.evidence_collector import EvidenceCollector


def main():

    print("=" * 60)
    print("       SMART IoT SECURITY SIMULATOR")
    print("=" * 60)

    # --------------------------------------------------
    # CREATE DEVICES
    # --------------------------------------------------

    clock = SmartClock("CLOCK_001")

    temperature = TemperatureSensor("TEMP_001")

    motion = MotionSensor("MOTION_001")

    camera = Camera("CAM_001")

    # --------------------------------------------------
    # CREATE RASPBERRY PI
    # --------------------------------------------------

    raspberry_pi = RaspberryPi()

    # --------------------------------------------------
    # CREATE TRUST MANAGER
    # --------------------------------------------------

    trust_manager = TrustManager()

    trust_manager.register_device(
        "CLOCK_001"
    )

    trust_manager.register_device(
        "TEMP_001"
    )

    trust_manager.register_device(
        "MOTION_001"
    )

    trust_manager.register_device(
        "CAM_001"
    )

    # --------------------------------------------------
    # CREATE FORENSIC SYSTEM
    # --------------------------------------------------

    evidence_collector = EvidenceCollector()

    # --------------------------------------------------
    # CREATE GATEWAY
    # --------------------------------------------------

    gateway = Gateway(
        trust_manager,
        evidence_collector
    )

    # --------------------------------------------------
    # CREATE ATTACK SIMULATOR
    # --------------------------------------------------

    attack_simulator = AttackSimulator()

    # --------------------------------------------------
    # DEVICE LIST
    # --------------------------------------------------

    devices = [

        clock,
        temperature,
        motion,
        camera

    ]

    # --------------------------------------------------
    # SIMULATION
    # --------------------------------------------------

    for iteration in range(1, 16):

        print("\n")
        print("=" * 60)

        print(
            f"SIMULATION ROUND {iteration}"
        )

        print("=" * 60)

        # --------------------------------------------------
        # ATTACK AFTER ROUND 5
        # --------------------------------------------------

        if iteration == 6:

            attack_simulator.compromise_device(
                "MOTION_001"
            )

        # --------------------------------------------------
        # GENERATE DEVICE DATA
        # --------------------------------------------------

        for device in devices:

            data = device.generate_data()

            # Check whether attacker has compromised device
            data = attack_simulator.generate_malicious_data(
                data
            )

            # Send to Raspberry Pi
            raspberry_pi.receive_data(
                data
            )

        # --------------------------------------------------
        # SEND DATA FROM RASPBERRY PI TO GATEWAY
        # --------------------------------------------------

        while len(raspberry_pi.device_data) > 0:

            raspberry_pi.send_to_gateway(
                gateway
            )

        # --------------------------------------------------
        # DISPLAY TRUST TABLE
        # --------------------------------------------------

        print("\nCURRENT DEVICE TRUST")

        print("-" * 60)

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

        time.sleep(2)


if __name__ == "__main__":

    main()