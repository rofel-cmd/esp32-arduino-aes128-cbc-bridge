#include "esp_random.h"
#include "mbedtls/aes.h"
#include "BluetoothSerial.h"
#include <ControlProtocol.h>
#include <CapstoneConfig.h>

using namespace ControlProtocol;

// Configuration
const int MAX_CONNECTION_ATTEMPTS = 3;

BluetoothSerial SerialBT;

// One outstanding control command. Command IDs count up from a random nonzero
// boot seed; that is operator correlation, not replay protection.
Pending pending;
uint32_t nextCommandId = 1;

// Nonblocking line buffers: USB verbs in, plaintext Bluetooth responses back.
char usbLine[64];
size_t usbLen = 0;
char btLine[RESPONSE_CAPACITY + 16];
size_t btLen = 0;

/**
 * @brief Generates a 16-byte True Random Number Generator (TRNG) IV.
 * Uses ESP32's hardware TRNG (esp_random).
 */
void generateTRNG_IV(uint8_t *iv) {
    for (int i = 0; i < 16; i += 4) {
        uint32_t r = esp_random();
        memcpy(iv + i, &r, 4);
    }
}

/**
 * @brief Adds PKCS#7 padding to the input data.
 */
int addPKCS7Padding(uint8_t *input, int inputLen, uint8_t *output) {
    int padding = 16 - (inputLen % 16);
    memcpy(output, input, inputLen);
    for (int i = 0; i < padding; i++) {
        output[inputLen + i] = (uint8_t)padding;
    }
    return inputLen + padding;
}

/**
 * @brief Encrypts data using AES-128-CBC with hardware acceleration via mbedtls.
 */
void encryptAES128_CBC(uint8_t *plaintext, int length, uint8_t *key, uint8_t *iv, uint8_t *ciphertext) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16); // mbedtls modifies IV, so we use a copy

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv_copy, plaintext, ciphertext);

    mbedtls_aes_free(&aes);
}

/**
 * @brief Measures performance of AES encryption.
 * Target: ~7.07 us/byte.
 */
void measurePerformance(int dataLength, uint32_t startTime, uint32_t endTime) {
    float duration = (float)(endTime - startTime);
    float usPerByte = duration / dataLength;
    Serial.print("Encryption Performance: ");
    Serial.print(usPerByte);
    Serial.println(" us/byte");
}

/**
 * @brief Accumulates bytes from `in` until LF. Strips CR. Returns true once a
 * complete line sits NUL-terminated in `buf`; `len` is then reset for the next
 * line. Bytes past the buffer are dropped so a flood cannot overrun.
 */
bool pumpLine(Stream &in, char *buf, size_t cap, size_t &len) {
    while (in.available()) {
        char c = (char)in.read();
        if (c == '\r') continue;
        if (c == '\n') {
            buf[len] = '\0';
            len = 0;
            return true;
        }
        if (len + 1 < cap) {
            buf[len++] = c;
        }
    }
    return false;
}

/**
 * @brief Builds CMD|<id>|<verb>, encrypts it with a fresh IV over the existing
 * [IV(16)][LEN(2)][ciphertext] transport, arms the 3000 ms deadline immediately
 * before the first frame byte, and writes the frame. No plaintext command is
 * echoed over Bluetooth.
 */
void sendCommand(bool activate) {
    uint32_t id = nextCommandId;
    nextCommandId++;
    if (nextCommandId == 0) nextCommandId = 1;

    char command[COMMAND_CAPACITY];
    formatCommand(command, sizeof(command), id, activate);
    int msgLen = (int)strlen(command);
    uint16_t commandCrc = crc16((const uint8_t *)command, (size_t)msgLen);

    int paddedLen = ((msgLen / 16) + 1) * 16;
    uint8_t plaintext[COMMAND_CAPACITY + 16];
    uint8_t ciphertext[COMMAND_CAPACITY + 16];
    uint8_t iv[16];

    // 1. Generate TRNG IV
    generateTRNG_IV(iv);

    // 2. Prepare Data (Padding)
    addPKCS7Padding((uint8_t *)command, msgLen, plaintext);

    // 3. Encrypt & Measure
    uint32_t start = micros();
    encryptAES128_CBC(plaintext, paddedLen, CAPSTONE_AES128_DEMO_KEY, iv, ciphertext);
    uint32_t end = micros();
    measurePerformance(paddedLen, start, end);

    // 4. Arm the deadline, then write [IV(16)][LEN_HI][LEN_LO][Ciphertext].
    pending.begin(id, activate, commandCrc, millis());
    SerialBT.write(iv, 16);
    SerialBT.write((uint8_t)(paddedLen >> 8));
    SerialBT.write((uint8_t)(paddedLen & 0xFF));
    SerialBT.write(ciphertext, paddedLen);

    Serial.print("SENT id=");
    Serial.print(id, HEX);
    Serial.print(" verb=");
    Serial.println(activate ? "ACTIVATE" : "DEACTIVATE");
}

void handleUsbLine(const char *line) {
    if (line[0] == '\0') return;

    bool activate;
    if (strcmp(line, "ACTIVATE") == 0) {
        activate = true;
    } else if (strcmp(line, "DEACTIVATE") == 0) {
        activate = false;
    } else {
        Serial.println("ERROR: only ACTIVATE or DEACTIVATE are accepted.");
        return;
    }

    if (!SerialBT.connected()) {
        Serial.println("ERROR: message not sent because Bluetooth is disconnected.");
        return;
    }

    sendCommand(activate);
}

void handleBtLine(const char *line) {
    Reply reply;
    if (!parseResponse(line, strlen(line), reply)) {
        Serial.println("IGNORED: malformed response line.");
        return;
    }
    if (!pending.matches(reply)) {
        Serial.println("IGNORED: response does not match the outstanding command.");
        return;
    }

    uint32_t rtt = millis() - pending.start;
    Serial.print("MATCH id=");
    Serial.print(reply.id, HEX);
    Serial.print(" state=");
    Serial.print(reply.active ? "ACTIVE" : "INACTIVE");
    Serial.print(" rtt_ms=");
    Serial.println(rtt);
    pending.clear();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("ESP32 encrypted control master");
    Serial.println("Target: configured HC-05 receiver");
    Serial.println("Commands: ACTIVATE or DEACTIVATE, one outstanding, 3000 ms timeout.");

    uint32_t seed = esp_random();
    if (seed == 0) seed = 1;
    nextCommandId = seed;

    if (!SerialBT.begin("ESP32_MASTER", true)) {
        Serial.println("ERROR: Bluetooth Classic initialization failed.");
        return;
    }
    if (!SerialBT.setPin(CAPSTONE_PAIRING_PIN, sizeof(CAPSTONE_PAIRING_PIN) - 1)) {
        Serial.println("ERROR: legacy pairing PIN setup failed.");
        return;
    }

    for (int attempt = 1; attempt <= MAX_CONNECTION_ATTEMPTS; ++attempt) {
        Serial.print("Connection attempt ");
        Serial.print(attempt);
        Serial.print(" of ");
        Serial.println(MAX_CONNECTION_ATTEMPTS);

        if (SerialBT.connect(CAPSTONE_HC05_ADDRESS)) {
            Serial.println("Connected to configured HC-05 receiver.");
            return;
        }

        Serial.println("Connection failed.");
        delay(1000);
    }

    Serial.println("ERROR: unable to connect after 3 attempts. Reset ESP32 to retry.");
}

void loop() {
    // USB input is consumed only while no command is outstanding; a second
    // command is rejected, never queued.
    if (!pending.armed) {
        if (pumpLine(Serial, usbLine, sizeof(usbLine), usbLen)) {
            handleUsbLine(usbLine);
        }
    } else if (pumpLine(Serial, usbLine, sizeof(usbLine), usbLen)) {
        Serial.println("BUSY: a command is already outstanding; input rejected.");
    }

    // Plaintext response line from the Arduino via HC-05.
    if (pumpLine(SerialBT, btLine, sizeof(btLine), btLen)) {
        handleBtLine(btLine);
    }

    // Terminal outcomes for the outstanding command. State is unknown on either;
    // never retry automatically.
    if (pending.armed) {
        if (!SerialBT.connected()) {
            Serial.print("DISCONNECTED id=");
            Serial.print(pending.id, HEX);
            Serial.println(" link lost; command state unknown.");
            pending.clear();
        } else if (pending.expired(millis())) {
            Serial.print("TIMEOUT id=");
            Serial.print(pending.id, HEX);
            Serial.println(" no matching response in 3000 ms; command state unknown.");
            pending.clear();
        }
    }

    delay(2);
}
