#include <AES.h>
#include <SoftwareSerial.h>
#include <ControlProtocol.h>
#include <CapstoneConfig.h>
#include "ReceiverSafety.h"

using namespace ControlProtocol;
using namespace ReceiverSafety;

// Configuration
SoftwareSerial BTSerial(10, 11);  // RX, TX; Arduino TX reaches HC-05 RX through the divider.

// Simulated actuator state; starts INACTIVE. No physical actuator is driven.
bool simActive = false;

AES128 aes128;

/**
 * @brief Decrypts data using AES-128-CBC.
 * Software implementation for Arduino Uno.
 */
void decryptAES128_CBC(uint8_t *ciphertext, int length, uint8_t *key, uint8_t *iv, uint8_t *plaintext) {
  aes128.setKey(key, 16);

  uint8_t prev_block[16];
  memcpy(prev_block, iv, 16);

  for (int i = 0; i < length; i += 16) {
    uint8_t current_block[16];
    memcpy(current_block, ciphertext + i, 16);

    aes128.decryptBlock(plaintext + i, ciphertext + i);

    // XOR with previous block (CBC mode)
    for (int j = 0; j < 16; j++) {
      plaintext[i + j] ^= prev_block[j];
    }

    memcpy(prev_block, current_block, 16);
  }
}

/**
 * @brief Measures performance of AES decryption.
 * Target: ~33.28 us/byte.
 */
void measurePerformance(int dataLength, uint32_t startTime, uint32_t endTime) {
  float duration = (float)(endTime - startTime);
  float usPerByte = duration / dataLength;
  Serial.print("Decryption Performance: ");
  Serial.print(usPerByte);
  Serial.println(" us/byte");
}

void setup() {
  Serial.begin(9600);
  BTSerial.begin(9600);  // HC-06 default baud rate
  Serial.println("Arduino Slave Initialized. Waiting for ESP32...");
}

// Read exactly `len` bytes from BTSerial with a timeout.
// Returns true on success, false if timeout expires.
bool readExact(uint8_t *buf, int len, unsigned long timeout_ms) {
  const unsigned long start = millis();
  int received = 0;
  while (received < len) {
    if (timeoutExpired(start, millis(), timeout_ms)) return false;
    if (BTSerial.available()) {
      buf[received++] = BTSerial.read();
    }
  }
  return true;
}

void loop() {
  if (BTSerial.available() > 0) {
    // 1. Read IV (16 bytes) with 500 ms timeout
    uint8_t iv[16];
    if (!readExact(iv, 16, 500)) {
      Serial.println("Timeout reading IV — discarding.");
      return;
    }

    // 2. Read length prefix (2 bytes, big-endian) sent by master
    uint8_t len_buf[2];
    if (!readExact(len_buf, 2, 500)) {
      Serial.println("Timeout reading length — discarding.");
      return;
    }
    int ciphertextLen = ((int)len_buf[0] << 8) | len_buf[1];
    if (ciphertextLen == 0 || ciphertextLen > 256 || ciphertextLen % 16 != 0) {
      Serial.println("Invalid ciphertext length — discarding.");
      return;
    }

    uint8_t ciphertext[256];
    uint8_t plaintext[256];

    // 3. Read ciphertext with 1000 ms timeout
    if (!readExact(ciphertext, ciphertextLen, 1000)) {
      Serial.println("Timeout reading ciphertext — discarding.");
      return;
    }

    // 2. Decrypt & Measure
    uint32_t start = micros();
    decryptAES128_CBC(ciphertext, ciphertextLen, CAPSTONE_AES128_DEMO_KEY, iv, plaintext);
    uint32_t end = micros();

    measurePerformance(ciphertextLen, start, end);

    // 3. Handle Padding
    size_t actualLen;
    if (!validPkcs7(plaintext, (size_t)ciphertextLen, actualLen)) {
      Serial.println(F("Invalid PKCS#7 padding — discarding."));
      return;
    }

    Serial.print("Received Decrypted Message: ");
    for (size_t i = 0; i < actualLen; i++) {
      Serial.print((char)plaintext[i]);
    }
    Serial.println();

    // Control callback: if the recovered plaintext is a well-formed command,
    // update the simulated state and return a plaintext, CRC-checked response
    // over Bluetooth. The return line is unauthenticated by design; the CRC
    // guards against accidental corruption only.
    Command command;
    if (parseCommand((const char *)plaintext, (size_t)actualLen, command)) {
      simActive = command.active;
      uint16_t commandCrc = crc16(plaintext, (size_t)actualLen);
      char response[RESPONSE_CAPACITY];
      if (formatResponse(response, sizeof(response), command.id, simActive, commandCrc)) {
        BTSerial.print(response);
        BTSerial.print('\n');
        Serial.print(F("Sent response: "));
        Serial.println(response);
      }
    } else {
      Serial.println(F("Recovered payload is not a control command; no response sent."));
    }
  }
}
