import hmac
import hashlib
import json


class LightweightCrypto:

    def __init__(self):

        # ====================================================
        # SIMULATION KEYS
        # ====================================================
        #
        # In the real IoT implementation, these keys should
        # be securely provisioned and stored on the device.
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