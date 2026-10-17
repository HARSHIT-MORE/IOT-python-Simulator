import time


class RaspberryPi:

    def __init__(self):
        self.device_data = []

    def receive_data(self, data):

        print("\n[RASPBERRY PI] Data received")
        print(data)

        self.device_data.append(data)

    def send_to_gateway(self, gateway):

        if len(self.device_data) == 0:
            return

        data = self.device_data.pop(0)

        print("[RASPBERRY PI] Sending data to Gateway")

        gateway.receive_data(data)

        time.sleep(0.2)