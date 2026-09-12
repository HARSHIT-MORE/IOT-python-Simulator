import os
import json
import time


class EvidenceCollector:

    def __init__(self, evidence_directory="evidence"):

        self.evidence_directory = evidence_directory

        os.makedirs(
            self.evidence_directory,
            exist_ok=True
        )

    def collect(self, device_id, event, trust_score):

        evidence = {

            "device_id": device_id,

            "event": event,

            "trust_score": round(trust_score, 3),

            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        file_path = os.path.join(
            self.evidence_directory,
            f"{device_id}_evidence.json"
        )

        with open(file_path, "a") as file:

            json.dump(
                evidence,
                file
            )

            file.write("\n")

        print(
            f"[FORENSICS] Evidence collected for {device_id}"
        )

        return evidence