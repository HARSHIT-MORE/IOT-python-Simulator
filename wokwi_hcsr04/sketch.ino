#include <WiFi.h>

#include <PubSubClient.h>

#include "DHTesp.h"

#include "time.h"
#include <string.h>
#include "mbedtls/md.h"

// =====================================================

// DEVICE PINS

// =====================================================

// DHT22

const int DHT_PIN = 15;

// HC-SR04 Ultrasonic Distance Sensor

const int TRIG_PIN = 18;
const int ECHO_PIN = 19;

// =====================================================

// DHT22

// =====================================================

DHTesp dhtSensor;

// =====================================================

// WIFI

// =====================================================

const char* WIFI_SSID = "Wokwi-GUEST";

const char* WIFI_PASSWORD = "";

// =====================================================

// MQTT

// =====================================================

const char* MQTT_SERVER = "broker.hivemq.com";

const int MQTT_PORT = 1883;

// =====================================================

// MQTT TOPICS

// =====================================================

const char* TEMP_TOPIC =

    "harshit/iot/TEMP_001";

const char* DISTANCE_TOPIC =

    "harshit/iot/DISTANCE_001";

const char* CLOCK_TOPIC =

    "harshit/iot/CLOCK_001";

const char* CAMERA_TOPIC =

    "harshit/iot/CAMERA_001";

// =====================================================

// NTP

// =====================================================

const char* NTP_SERVER = "pool.ntp.org";

// India = UTC + 5:30

const long GMT_OFFSET = 19800;

const int DAYLIGHT_OFFSET = 0;

// =====================================================

// MQTT OBJECT

// =====================================================

WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Message identity metadata: each device has its own sequence counter.
String bootId;
uint32_t tempSequence = 0;
uint32_t distanceSequence = 0;
uint32_t clockSequence = 0;
uint32_t cameraSequence = 0;

// Demo-only per-device HMAC keys. These must match security/crypto.py.
// Do NOT use these public/demo keys in a production deployment.
const char* deviceKeyForId(const char* deviceId) {
    if (strcmp(deviceId, "CLOCK_001") == 0) return "clock_secret_key";
    if (strcmp(deviceId, "TEMP_001") == 0) return "temperature_secret_key";
    if (strcmp(deviceId, "DISTANCE_001") == 0) return "distance_secret_key";
    if (strcmp(deviceId, "CAMERA_001") == 0) return "camera_secret_key";
    return nullptr;
}

String hmacSha256Hex(const String& message, const char* key) {
    if (key == nullptr) return "";
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return "";

    unsigned char digest[32];
    int rc = mbedtls_md_hmac(
        mdInfo,
        reinterpret_cast<const unsigned char*>(key), strlen(key),
        reinterpret_cast<const unsigned char*>(message.c_str()), message.length(),
        digest
    );
    if (rc != 0) return "";

    char hex[65];
    for (size_t i = 0; i < sizeof(digest); ++i) {
        snprintf(hex + (i * 2), 3, "%02x", digest[i]);
    }
    hex[64] = '\0';
    return String(hex);
}

// Add message identity and a device-origin Unix timestamp, then sign the exact
// JSON bytes before appending message_signature as the final JSON property.
// Python verifies those exact bytes; it must not re-serialize the JSON first.
bool finalizeAndSignMessage(String& message, const char* deviceId, uint32_t& sequenceNumber) {
    if (message.length() == 0 || message[message.length() - 1] != '}') {
        Serial.println("[HMAC] Cannot sign malformed JSON.");
        return false;
    }

    time_t epochNow = time(nullptr);
    if (epochNow < 1700000000) {
        Serial.println("[HMAC] NTP time is not synchronized; message withheld.");
        return false;
    }

    const char* key = deviceKeyForId(deviceId);
    if (key == nullptr) {
        Serial.println("[HMAC] No key configured for device; message withheld.");
        return false;
    }

    message.remove(message.length() - 1); // remove existing closing brace
    message += ",\"boot_id\":\"";
    message += bootId;
    message += "\",\"sequence_number\":";
    message += String(sequenceNumber);
    message += ",\"device_timestamp_epoch\":";
    message += String((uint32_t)epochNow);
    message += "}";

    // HMAC covers every device field, sequence metadata, and device timestamp.
    String signature = hmacSha256Hex(message, key);
    if (signature.length() != 64) {
        Serial.println("[HMAC] Signature generation failed; message withheld.");
        return false;
    }

    message.remove(message.length() - 1);
    message += ",\"message_signature\":\"";
    message += signature;
    message += "\"}";
    sequenceNumber++;
    return true;
}

// =====================================================

// CONNECT WIFI

// =====================================================

void connectWiFi() {

    Serial.println();

    Serial.println("====================================");

    Serial.println("Connecting to WiFi");

    Serial.println("====================================");

    WiFi.mode(WIFI_STA);

    WiFi.begin(

        WIFI_SSID,

        WIFI_PASSWORD,

        6

    );

    while (WiFi.status() != WL_CONNECTED) {

        delay(500);

        Serial.print(".");

    }

    Serial.println();

    Serial.println("WiFi connected!");

    Serial.print("ESP32 IP address: ");

    Serial.println(

        WiFi.localIP()

    );

}

// =====================================================

// CONNECT MQTT

// =====================================================

bool connectMQTT() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[MQTT] Cannot connect: Wi-Fi is disconnected.");
        return false;
    }

    if (mqttClient.connected()) {
        return true;
    }

    // Unique client ID reduces the chance of another client disconnecting us.
    String clientId = "WokwiIoT-";
    clientId += String((uint32_t)(ESP.getEfuseMac() & 0xFFFFFFFF), HEX);

    Serial.println();
    Serial.print("[MQTT] Connecting to ");
    Serial.print(MQTT_SERVER);
    Serial.print(":");
    Serial.println(MQTT_PORT);
    Serial.print("[MQTT] Client ID: ");
    Serial.println(clientId);

    bool connected = mqttClient.connect(clientId.c_str());
    if (connected) {
        Serial.println("[MQTT] CONNECTED successfully.");
        return true;
    }

    int state = mqttClient.state();
    Serial.print("[MQTT] Connection FAILED, state=");
    Serial.println(state);
    if (state == -4) {
        Serial.println("[MQTT] State -4: connection attempt timed out. Check broker reachability or try again.");
    } else if (state == -2) {
        Serial.println("[MQTT] State -2: network connection failed.");
    } else if (state == 4 || state == 5) {
        Serial.println("[MQTT] Broker rejected the connection (credentials/authorization). This broker is configured for anonymous testing here.");
    }
    return false;
}

// Publish non-retained messages while reporting delivery to the MQTT client.
// PubSubClient publish() returns whether the packet was accepted for sending;
// it is not an end-to-end broker acknowledgement (QoS 0).
bool publishMessage(const char* topic, const String& message) {
    if (!mqttClient.connected()) {
        Serial.println("[MQTT] Publish skipped: client is disconnected.");
        return false;
    }

    bool ok = mqttClient.publish(topic, message.c_str(), false); // retain=false for live-data debugging
    Serial.print("[MQTT] Publish ");
    Serial.print(topic);
    Serial.print(": ");
    Serial.println(ok ? "queued/sent" : "FAILED");
    return ok;
}

// =====================================================

// SETUP

// =====================================================

void setup() {

    Serial.begin(115200);

    // Unique for this ESP32 boot session; sequence counters restart at zero.
    bootId = String((uint32_t)(ESP.getEfuseMac() & 0xFFFFFFFF), HEX);
    bootId += "-";
    bootId += String(esp_random(), HEX);
    Serial.print("[MQTT] Boot ID: ");
    Serial.println(bootId);

    delay(1000);

    // -------------------------------------------------

    // Initialize DHT22

    // -------------------------------------------------

    dhtSensor.setup(

        DHT_PIN,

        DHTesp::DHT22

    );

    // -------------------------------------------------

    // Initialize PIR

    // -------------------------------------------------

    pinMode(TRIG_PIN, OUTPUT);
    digitalWrite(TRIG_PIN, LOW);
    pinMode(ECHO_PIN, INPUT);

    // -------------------------------------------------

    // Connect WiFi

    // -------------------------------------------------

    connectWiFi();

    // -------------------------------------------------

    // Configure MQTT

    // -------------------------------------------------

    mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
    mqttClient.setKeepAlive(30);
    mqttClient.setSocketTimeout(5);
    mqttClient.setBufferSize(512);

    // -------------------------------------------------

    // Connect MQTT

    // -------------------------------------------------

    connectMQTT();

    // -------------------------------------------------

    // Configure NTP clock

    // -------------------------------------------------

    configTime(

        GMT_OFFSET,

        DAYLIGHT_OFFSET,

        NTP_SERVER

    );

    Serial.println();

    Serial.println("====================================");

    Serial.println("ALL IoT DEVICES INITIALIZED");

    Serial.println("====================================");

    Serial.println("TEMP_001     -> DHT22");

    Serial.println("DISTANCE_001 -> HC-SR04");

    Serial.println("CLOCK_001    -> NTP Clock");

    Serial.println("CAMERA_001   -> Camera Simulator");

    Serial.println("====================================");

}

// =====================================================

// TEMPERATURE SENSOR

// =====================================================

void publishTemperature() {

    TempAndHumidity data =

        dhtSensor.getTempAndHumidity();

    // -------------------------------------------------

    // Display

    // -------------------------------------------------

    Serial.println();

    Serial.println("---------- TEMP_001 ----------");

    Serial.print(

        "Temperature: "

    );

    Serial.print(

        data.temperature

    );

    Serial.println(" °C");

    Serial.print(

        "Humidity: "

    );

    Serial.print(

        data.humidity

    );

    Serial.println(" %");

    // -------------------------------------------------

    // Create JSON

    // -------------------------------------------------

    String message = "{";

    message +=

        "\"device_id\":\"TEMP_001\",";

    message +=

        "\"device_type\":\"temperature_sensor\",";

    message +=

        "\"temperature\":";

    message +=

        String(

            data.temperature,

            2

        );

    message += ",";

    message +=

        "\"humidity\":";

    message +=

        String(

            data.humidity,

            2

        );

    message += ",";

    message +=

        "\"status\":\"normal\"";

    message += "}";

    // -------------------------------------------------

    // Publish

    // -------------------------------------------------

    if (finalizeAndSignMessage(message, "TEMP_001", tempSequence)) {
        publishMessage(TEMP_TOPIC, message);
    }

    Serial.print(

        "MQTT: "

    );

    Serial.println(

        message

    );

}

// =====================================================
// HC-SR04 DISTANCE SENSOR
// =====================================================

void publishDistance() {
    digitalWrite(TRIG_PIN, LOW);
    delayMicroseconds(2);
    digitalWrite(TRIG_PIN, HIGH);
    delayMicroseconds(10);
    digitalWrite(TRIG_PIN, LOW);

    // HC-SR04 measures echo pulse duration; 30ms covers its 400cm range.
    unsigned long echoDuration = pulseIn(ECHO_PIN, HIGH, 30000UL);
    if (echoDuration == 0) {
        Serial.println("[DISTANCE_001] No echo received; reading skipped.");
        return;
    }

    float distanceCm = echoDuration / 58.0f;
    if (distanceCm < 2.0f || distanceCm > 400.0f) {
        Serial.printf("[DISTANCE_001] Out-of-range reading %.2f cm; skipped.\n", distanceCm);
        return;
    }

    Serial.println();
    Serial.println("---------- DISTANCE_001 ----------");
    Serial.printf("Distance: %.2f cm\n", distanceCm);

    String message = "{";
    message += "\"device_id\":\"DISTANCE_001\",";
    message += "\"device_type\":\"ultrasonic_distance_sensor\",";
    message += "\"distance_cm\":";
    message += String(distanceCm, 2);
    message += ",\"status\":\"normal\"}";

    if (finalizeAndSignMessage(message, "DISTANCE_001", distanceSequence)) {
        publishMessage(DISTANCE_TOPIC, message);
    }
    Serial.print("MQTT: ");
    Serial.println(message);
}

// =====================================================

// SMART CLOCK

// =====================================================

void publishClock() {

    struct tm timeinfo;

    // -------------------------------------------------

    // Get current time

    // -------------------------------------------------

    if (

        !getLocalTime(

            &timeinfo

        )

    ) {

        Serial.println(

            "CLOCK_001: Time unavailable"

        );

        return;

    }

    // -------------------------------------------------

    // Extract time

    // -------------------------------------------------

    int hour =

        timeinfo.tm_hour;

    int minute =

        timeinfo.tm_min;

    int second =

        timeinfo.tm_sec;

    // -------------------------------------------------

    // Display

    // -------------------------------------------------

    Serial.println();

    Serial.println("---------- CLOCK_001 ----------");

    Serial.printf(

        "Time: %02d:%02d:%02d\n",

        hour,

        minute,

        second

    );

    // -------------------------------------------------

    // Create JSON

    // -------------------------------------------------

    String message = "{";

    message +=

        "\"device_id\":\"CLOCK_001\",";

    message +=

        "\"device_type\":\"smart_clock\",";

    message +=

        "\"hour\":";

    message +=

        String(hour);

    message += ",";

    message +=

        "\"minute\":";

    message +=

        String(minute);

    message += ",";

    message +=

        "\"second\":";

    message +=

        String(second);

    message += ",";

    message +=

        "\"status\":\"normal\"";

    message += "}";

    // -------------------------------------------------

    // Publish

    // -------------------------------------------------

    if (finalizeAndSignMessage(message, "CLOCK_001", clockSequence)) {
        publishMessage(CLOCK_TOPIC, message);
    }

    Serial.print(

        "MQTT: "

    );

    Serial.println(

        message

    );

}

// =====================================================

// CAMERA

// =====================================================

//

// This is currently a CAMERA SIMULATOR.

//

// We are not transmitting actual images.

// It generates camera-like observation metadata.

//

// Later this can be replaced with:

// ESP32-CAM / Raspberry Pi Camera.

// =====================================================

void publishCamera() {

    // -------------------------------------------------

    // Simulated camera observation

    // -------------------------------------------------

    bool objectDetected =

        random(0, 100) < 30;

    int imageSize =

        random(

            30000,

            90000

        );

    int fps = 10;

    // -------------------------------------------------

    // Display

    // -------------------------------------------------

    Serial.println();

    Serial.println("---------- CAMERA_001 ----------");

    Serial.print(

        "Object detected: "

    );

    if (objectDetected) {

        Serial.println(

            "YES"

        );

    }

    else {

        Serial.println(

            "NO"

        );

    }

    Serial.print(

        "FPS: "

    );

    Serial.println(

        fps

    );

    Serial.print(

        "Image size: "

    );

    Serial.print(

        imageSize

    );

    Serial.println(

        " bytes"

    );

    // -------------------------------------------------

    // Create JSON

    // -------------------------------------------------

    String message = "{";

    message +=

        "\"device_id\":\"CAMERA_001\",";

    message +=

        "\"device_type\":\"camera\",";

    message +=

        "\"object_detected\":";

    if (objectDetected) {

        message +=

            "true";

    }

    else {

        message +=

            "false";

    }

    message += ",";

    message +=

        "\"fps\":";

    message +=

        String(fps);

    message += ",";

    message +=

        "\"image_size_bytes\":";

    message +=

        String(imageSize);

    message += ",";

    message +=

        "\"status\":\"normal\"";

    message += "}";

    // -------------------------------------------------

    // Publish

    // -------------------------------------------------

    if (finalizeAndSignMessage(message, "CAMERA_001", cameraSequence)) {
        publishMessage(CAMERA_TOPIC, message);
    }

    Serial.print(

        "MQTT: "

    );

    Serial.println(

        message

    );

}

// =====================================================

// MAIN LOOP

// =====================================================

void loop() {
    static unsigned long lastReconnectAttempt = 0;

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WiFi] Disconnected; attempting reconnect...");
        WiFi.reconnect();
        delay(1000);
        return;
    }

    if (!mqttClient.connected()) {
        unsigned long now = millis();
        if (now - lastReconnectAttempt >= 5000 || lastReconnectAttempt == 0) {
            lastReconnectAttempt = now;
            connectMQTT();
        }
        delay(10);
        return; // Never publish sensor data while MQTT is disconnected.
    }

    mqttClient.loop();

    publishTemperature();
    mqttClient.loop();
    delay(300);

    publishDistance();
    mqttClient.loop();
    delay(300);

    publishClock();
    mqttClient.loop();
    delay(300);

    publishCamera();
    mqttClient.loop();

    Serial.println();
    Serial.println("====================================");
    Serial.println("Sensor publishing cycle completed.");
    Serial.println("====================================");

    // Publish approximately every 5 seconds while allowing MQTT servicing.
    for (int i = 0; i < 50; ++i) {
        mqttClient.loop();
        delay(100);
        if (!mqttClient.connected()) {
            break;
        }
    }
}
