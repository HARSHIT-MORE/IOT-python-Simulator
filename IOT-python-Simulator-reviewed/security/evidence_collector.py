import os
import json
import time
import hashlib
import uuid


class EvidenceCollector:

    def __init__(self, evidence_directory="evidence"):

        self.evidence_directory = evidence_directory

        os.makedirs(
            self.evidence_directory,
            exist_ok=True
        )

    def _generate_hash(self, evidence):

        evidence_copy = evidence.copy()

        # Hash should not depend on the hash itself
        evidence_copy.pop("evidence_hash", None)

        evidence_string = json.dumps(
            evidence_copy,
            sort_keys=True
        )

        return hashlib.sha256(
            evidence_string.encode("utf-8")
        ).hexdigest()

    def collect(
        self,
        device_id,
        event,
        trust_score,
        risk_score=None,
        resource_state=None,
        device_state=None
    ):

        evidence = {

            "evidence_id": str(uuid.uuid4()),

            "timestamp": time.time(),

            "device_id": device_id,

            "event": event,

            "trust_score": trust_score,

            "risk_score": risk_score,

            "resource_state": resource_state,

            "device_state": device_state
        }

        # Generate integrity hash
        evidence["evidence_hash"] = self._generate_hash(
            evidence
        )

        # Create filename
        filename = (
            f"{evidence['evidence_id']}.json"
        )

        filepath = os.path.join(
            self.evidence_directory,
            filename
        )

        # Store evidence
        with open(
            filepath,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                evidence,
                file,
                indent=4
            )

        return evidence

    def verify_integrity(self, filepath):

        try:

            with open(
                filepath,
                "r",
                encoding="utf-8"
            ) as file:

                evidence = json.load(file)

            stored_hash = evidence.get(
                "evidence_hash"
            )

            calculated_hash = self._generate_hash(
                evidence
            )

            return stored_hash == calculated_hash

        except Exception as e:

            print(
                f"Evidence verification failed: {e}"
            )

            return False