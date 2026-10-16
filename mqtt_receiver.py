import paho.mqtt.client as mqtt

from iot.mqtt_adapter import MQTTDeviceAdapter


# ============================================================
# MQTT CONFIGURATION
# ============================================================

MQTT_BROKER = "test.mosquitto.org"
MQTT_PORT = 1883

# Receive all four device streams:
# TEMP_001, MOTION_001, CLOCK_001, CAMERA_001
MQTT_TOPIC = "harshit/iot/#"


# ============================================================
# MQTT ADAPTER
# ============================================================

adapter = MQTTDeviceAdapter()


# ============================================================
# MQTT CONNECT CALLBACK
# ============================================================

def on_connect(
    client,
    userdata,
    flags,
    reason_code,
    properties
):

    if reason_code == 0:

        print(
            "\nConnected to MQTT broker"
        )

        client.subscribe(
            MQTT_TOPIC
        )

        print(
            f"Subscribed to: {MQTT_TOPIC}"
        )

    else:

        print(
            f"MQTT connection failed: {reason_code}"
        )


# ============================================================
# MQTT MESSAGE CALLBACK
# ============================================================

def on_message(
    client,
    userdata,
    msg
):

    payload = msg.payload.decode(
        "utf-8",
        errors="replace"
    )

    # The adapter requires both the MQTT topic and payload.
    observation = adapter.process_message(
        msg.topic,
        payload
    )

    if observation is None:

        return

    print(
        "\n" + "=" * 60
    )

    print(
        f"Topic        : {msg.topic}"
    )

    print(
        f"Device       : "
        f"{observation['device_id']}"
    )

    print(
        f"Device type  : "
        f"{observation['device_type']}"
    )

    print(
        f"Source       : "
        f"{observation['source']}"
    )

    # --------------------------------------------------------
    # Device-specific ESP32 readings
    # --------------------------------------------------------

    device_type = observation[
        "device_type"
    ]

    if device_type == "temperature_sensor":

        print(
            f"Temperature  : "
            f"{observation.get('temperature')} °C"
        )

        print(
            f"Humidity     : "
            f"{observation.get('humidity')} %"
        )

    elif device_type == "motion_sensor":

        print(
            f"Motion       : "
            f"{observation.get('motion_detected')}"
        )

    elif device_type == "smart_clock":

        print(
            f"Time         : "
            f"{observation.get('hour')}:"
            f"{observation.get('minute')}:"
            f"{observation.get('second')}"
        )

    elif device_type == "camera":

        print(
            f"Object       : "
            f"{observation.get('object_detected')}"
        )

        print(
            f"FPS          : "
            f"{observation.get('fps')}"
        )

        print(
            f"Image size   : "
            f"{observation.get('image_size_bytes')} bytes"
        )

    print(
        "=" * 60
    )


# ============================================================
# MQTT CLIENT
# ============================================================

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2
)

client.on_connect = on_connect
client.on_message = on_message


# ============================================================
# START RECEIVER
# ============================================================

try:

    print(
        "Connecting to MQTT broker..."
    )

    client.connect(
        MQTT_BROKER,
        MQTT_PORT,
        60
    )

    print(
        "Starting MQTT receiver..."
    )

    client.loop_forever()

except KeyboardInterrupt:

    print(
        "\nMQTT receiver stopped by user."
    )

except Exception as exc:

    print(
        f"\nMQTT receiver error: {exc}"
    )

finally:

    try:
        client.disconnect()
    except Exception:
        pass
