class TrustManager:

    def __init__(self):

        self.trust_scores = {}

    def register_device(self, device_id, initial_score=0.95):

        self.trust_scores[device_id] = initial_score

    def get_trust_score(self, device_id):

        return self.trust_scores.get(device_id, 0.0)

    def decrease_trust(self, device_id, amount):

        if device_id in self.trust_scores:

            self.trust_scores[device_id] -= amount

            if self.trust_scores[device_id] < 0:
                self.trust_scores[device_id] = 0

    def increase_trust(self, device_id, amount):

        if device_id in self.trust_scores:

            self.trust_scores[device_id] += amount

            if self.trust_scores[device_id] > 1:
                self.trust_scores[device_id] = 1

    def get_status(self, device_id):

        score = self.get_trust_score(device_id)

        if score >= 0.7:
            return "TRUSTED"

        elif score >= 0.3:
            return "SUSPICIOUS"

        else:
            return "COMPROMISED"