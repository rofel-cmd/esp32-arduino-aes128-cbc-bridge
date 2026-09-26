#ifndef CONTROL_PROTOCOL_H
#define CONTROL_PROTOCOL_H

// Shared command/response codec for the ESP32 -> Arduino control callback.
//
// Wire grammar (ASCII, exact, no surrounding whitespace):
//   command  : "CMD|" <8 uppercase hex id> "|" ("ACTIVATE" | "DEACTIVATE")
//   response : "RSP|" <8 uppercase hex id> "|" ("ACTIVE" | "INACTIVE") "|"
//              <4 uppercase hex crc>
//
// The command travels inside the existing [IV(16)][LEN(2)][AES-CBC] transport.
// The response line is transmitted plaintext over Bluetooth and terminated by a
// single LF. crc is CRC-16/CCITT-FALSE over the entire recovered command string,
// id included; it guards against accidental corruption only, never against a
// forged or replayed reply. The return path carries no authentication by design.
//
// One command is outstanding at a time. A second command is rejected, not
// queued. The 3000 ms deadline starts immediately before the first Bluetooth
// frame write and is wrap-safe across the millis() rollover.
//
// Header-only, no dynamic allocation, no exceptions. Compiles as host C++11 and
// under avr-g++ / xtensa-esp-elf-g++ with the Arduino core.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace ControlProtocol {

// No matching response within this many milliseconds is a timeout.
static const uint32_t TIMEOUT_MS = 3000;

// Buffer sizes, terminating NUL included.
//   longest command  : "CMD|" + 8 + "|" + "DEACTIVATE"(10)          = 23 -> 24
//   longest response : "RSP|" + 8 + "|" + "INACTIVE"(8) + "|" + 4   = 26 -> 28
static const size_t COMMAND_CAPACITY = 24;
static const size_t RESPONSE_CAPACITY = 28;

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
inline uint16_t crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; ++i) {
    crc ^= (uint16_t)((uint16_t)data[i] << 8);
    for (uint8_t bit = 0; bit < 8; ++bit) {
      if (crc & 0x8000) {
        crc = (uint16_t)((uint16_t)(crc << 1) ^ 0x1021);
      } else {
        crc = (uint16_t)(crc << 1);
      }
    }
  }
  return crc;
}

inline bool parseHexDigit(char c, uint8_t &out) {
  if (c >= '0' && c <= '9') {
    out = (uint8_t)(c - '0');
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    out = (uint8_t)(c - 'A' + 10);
    return true;
  }
  return false;
}

// Parse exactly `digits` uppercase hex characters into `out`.
inline bool parseHex(const char *p, size_t digits, uint32_t &out) {
  uint32_t value = 0;
  for (size_t i = 0; i < digits; ++i) {
    uint8_t nibble;
    if (!parseHexDigit(p[i], nibble)) return false;
    value = (value << 4) | nibble;
  }
  out = value;
  return true;
}

// Write `digits` uppercase hex characters, zero-padded, most significant first.
inline void writeHex(char *p, size_t digits, uint32_t value) {
  const char *const kHex = "0123456789ABCDEF";
  for (size_t i = digits; i > 0; --i) {
    p[i - 1] = kHex[value & 0xF];
    value >>= 4;
  }
}

inline bool hasNul(const char *p, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (p[i] == '\0') return true;
  }
  return false;
}

struct Command {
  uint32_t id;
  bool active;
};

// Parse exactly `len` bytes; does not rely on NUL termination. Rejects an
// embedded NUL, a wrong prefix, a zero id, a non-uppercase-hex id, an unknown
// verb, or any trailing byte.
inline bool parseCommand(const char *input, size_t len, Command &out) {
  const size_t kMin = 4 + 8 + 1 + 8;  // "CMD|........|ACTIVATE"
  if (len < kMin) return false;
  if (hasNul(input, len)) return false;
  if (memcmp(input, "CMD|", 4) != 0) return false;
  if (input[12] != '|') return false;

  uint32_t id;
  if (!parseHex(input + 4, 8, id)) return false;
  if (id == 0) return false;

  const char *verb = input + 13;
  size_t verbLen = len - 13;
  bool active;
  if (verbLen == 8 && memcmp(verb, "ACTIVATE", 8) == 0) {
    active = true;
  } else if (verbLen == 10 && memcmp(verb, "DEACTIVATE", 10) == 0) {
    active = false;
  } else {
    return false;
  }

  out.id = id;
  out.active = active;
  return true;
}

// Write "CMD|<id>|<verb>" plus NUL. Returns false if `cap` is too small.
inline bool formatCommand(char *buf, size_t cap, uint32_t id, bool active) {
  const char *verb = active ? "ACTIVATE" : "DEACTIVATE";
  size_t verbLen = strlen(verb);
  size_t need = 13 + verbLen + 1;
  if (cap < need) return false;
  memcpy(buf, "CMD|", 4);
  writeHex(buf + 4, 8, id);
  buf[12] = '|';
  memcpy(buf + 13, verb, verbLen + 1);
  return true;
}

struct Reply {
  uint32_t id;
  bool active;
  uint16_t crc;
};

// Write "RSP|<id>|<state>|<crc>" plus NUL. Returns false if `cap` is too small.
inline bool formatResponse(char *buf, size_t cap, uint32_t id, bool active,
                           uint16_t crc) {
  const char *state = active ? "ACTIVE" : "INACTIVE";
  size_t stateLen = strlen(state);
  size_t need = 13 + stateLen + 1 + 4 + 1;
  if (cap < need) return false;
  memcpy(buf, "RSP|", 4);
  writeHex(buf + 4, 8, id);
  buf[12] = '|';
  size_t pos = 13;
  memcpy(buf + pos, state, stateLen);
  pos += stateLen;
  buf[pos++] = '|';
  writeHex(buf + pos, 4, crc);
  pos += 4;
  buf[pos] = '\0';
  return true;
}

// Parse exactly `len` bytes. Rejects an embedded NUL, a wrong prefix, a zero id,
// a non-uppercase-hex id, an unknown state, a CRC field that is not exactly four
// uppercase hex digits, or any trailing byte.
inline bool parseResponse(const char *buf, size_t len, Reply &out) {
  const size_t kMin = 4 + 8 + 1 + 6 + 1 + 4;  // "RSP|........|ACTIVE|XXXX"
  if (len < kMin) return false;
  if (hasNul(buf, len)) return false;
  if (memcmp(buf, "RSP|", 4) != 0) return false;
  if (buf[12] != '|') return false;

  uint32_t id;
  if (!parseHex(buf + 4, 8, id)) return false;
  if (id == 0) return false;

  const char *rest = buf + 13;
  size_t restLen = len - 13;
  bool active;
  size_t stateLen;
  if (restLen >= 7 && memcmp(rest, "ACTIVE|", 7) == 0) {
    active = true;
    stateLen = 6;
  } else if (restLen >= 9 && memcmp(rest, "INACTIVE|", 9) == 0) {
    active = false;
    stateLen = 8;
  } else {
    return false;
  }

  size_t crcOffset = 13 + stateLen + 1;
  if (len - crcOffset != 4) return false;
  uint32_t crc;
  if (!parseHex(buf + crcOffset, 4, crc)) return false;

  out.id = id;
  out.active = active;
  out.crc = (uint16_t)crc;
  return true;
}

// One outstanding command with a wrap-safe millisecond deadline.
struct Pending {
  bool armed;
  uint32_t id;
  bool active;
  uint16_t crc;
  uint32_t start;

  Pending() : armed(false), id(0), active(false), crc(0), start(0) {}

  // Arm for a new command. Returns false if one is already outstanding (so the
  // caller rejects the second command) or if `commandId` is zero.
  bool begin(uint32_t commandId, bool commandActive, uint16_t commandCrc,
             uint32_t startMillis) {
    if (armed) return false;
    if (commandId == 0) return false;
    armed = true;
    id = commandId;
    active = commandActive;
    crc = commandCrc;
    start = startMillis;
    return true;
  }

  // True only for a reply whose id, state and command CRC all match.
  bool matches(const Reply &reply) const {
    if (!armed) return false;
    return reply.id == id && reply.active == active && reply.crc == crc;
  }

  // Wrap-safe: true once at least TIMEOUT_MS has elapsed since `start`.
  bool expired(uint32_t nowMillis) const {
    if (!armed) return false;
    return (uint32_t)(nowMillis - start) >= TIMEOUT_MS;
  }

  void clear() {
    armed = false;
    id = 0;
    active = false;
    crc = 0;
    start = 0;
  }
};

}  // namespace ControlProtocol

#endif  // CONTROL_PROTOCOL_H
