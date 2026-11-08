import hmac
import hashlib
import json


class LightweightCrypto:

    def __init__(self):

        # ====================================================
        # SIMULATION KEYS
        # ====================================================
        #
        # In this Python simulator, these keys are simulation-only.
        # A signature counts as device-origin only if the device/firmware
        # computes it before publishing. A gateway-generated signature over
        # an already-received payload does not prove origin authenticity.
        # Real keys must be securely provisioned and stored on each device.
        #
        # HMAC-SHA256 is being used here for message
        # authentication and integrity.
        #
        # Authentication != Trust
        #
        # A compromised device can still possess a valid key.
        # Therefore, HMAC success alone must NOT result in
        # an ALLOW decision.
        # ====================================================

        self.device_keys = {

            "CLOCK_001":
                b"clock_secret_key",

            "TEMP_001":
                b"temperature_secret_key",

            "MOTION_001":
                b"motion_secret_key",

            "CAMERA_001":
                b"camera_secret_key"

        }


    # ========================================================
    # GET DEVICE KEY
    # ========================================================

    def get_key(
        self,
        device_id
    ):

        return self.device_keys.get(
            device_id
        )


    # ========================================================
    # SERIALIZE DATA
    # ========================================================

    def serialize_data(
        self,
        data
    ):

        return json.dumps(
            data,
            sort_keys=True,
            separators=(
                ",",
                ":"
            )
        ).encode(
            "utf-8"
        )


    # ========================================================
    # GENERATE HMAC
    # ========================================================

    def generate_hmac(
        self,
        device_id,
        data
    ):

        key = self.get_key(
            device_id
        )


        # ----------------------------------------------------
        # Unknown device
        # ----------------------------------------------------

        if key is None:

            return None


        # ----------------------------------------------------
        # Convert data into deterministic byte representation
        # ----------------------------------------------------

        message = self.serialize_data(
            data
        )


        # ----------------------------------------------------
        # HMAC-SHA256
        # ----------------------------------------------------

        signature = hmac.new(

            key,

            message,

            hashlib.sha256

        ).hexdigest()


        return signature


    # ========================================================
    # VERIFY HMAC
    # ========================================================

    def verify_hmac(
        self,
        device_id,
        data,
        received_signature
    ):

        # ----------------------------------------------------
        # Generate expected signature from received data
        # ----------------------------------------------------

        expected_signature = (
            self.generate_hmac(
                device_id,
                data
            )
        )


        # ----------------------------------------------------
        # Unknown device
        # ----------------------------------------------------

        if expected_signature is None:

            return False


        # ----------------------------------------------------
        # Missing signature
        # ----------------------------------------------------

        if received_signature is None:

            return False


        # ----------------------------------------------------
        # Constant-time comparison
        # ----------------------------------------------------

        return hmac.compare_digest(

            expected_signature,

            received_signature

        )


    def verify_hmac_raw_payload(self, device_id, raw_payload, received_signature):
        """Verify a signature over the exact raw JSON bytes signed by firmware.

        The firmware appends message_signature as the final JSON property.
        This method removes only that final property to recover the signed bytes.
        """
        key = self.get_key(device_id)
        if key is None or not isinstance(raw_payload, str) or not isinstance(received_signature, str):
            return False
        marker = ',"message_signature":"'
        marker_index = raw_payload.rfind(marker)
        if marker_index < 0 or not raw_payload.endswith('"}'):
            return False
        raw_signature = raw_payload[marker_index + len(marker):-2]
        if raw_signature != received_signature or len(raw_signature) != 64:
            return False
        signed_payload = raw_payload[:marker_index] + "}"
        expected = hmac.new(key, signed_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, raw_signature)

    # ========================================================
    # AUTHENTICATE MESSAGE
    # ========================================================

    def authenticate_message(
        self,
        device_id,
        data
    ):

        signature = (
            self.generate_hmac(
                device_id,
                data
            )
        )


        # ----------------------------------------------------
        # Unknown device
        # ----------------------------------------------------

        if signature is None:

            return {

                "authenticated":
                    False,

                "signature":
                    None,

                "reason":
                    "Unknown device"

            }


        # ----------------------------------------------------
        # Successful authentication
        # ----------------------------------------------------

        return {

            "authenticated":
                True,

            "signature":
                signature,

            "reason":
                "HMAC-SHA256 generated successfully"

        }