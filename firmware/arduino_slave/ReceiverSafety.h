#ifndef RECEIVER_SAFETY_H
#define RECEIVER_SAFETY_H

#include <stddef.h>
#include <stdint.h>

namespace ReceiverSafety {

inline bool validPkcs7(const uint8_t *data, size_t length, size_t &unpaddedLength) {
  if (data == 0 || length == 0 || (length % 16) != 0) return false;

  const uint8_t padding = data[length - 1];
  if (padding == 0 || padding > 16 || padding > length) return false;

  for (size_t i = length - padding; i < length; ++i) {
    if (data[i] != padding) return false;
  }

  unpaddedLength = length - padding;
  return true;
}

inline bool timeoutExpired(uint32_t start, uint32_t now, uint32_t timeoutMs) {
  return (uint32_t)(now - start) >= timeoutMs;
}

}  // namespace ReceiverSafety

#endif
