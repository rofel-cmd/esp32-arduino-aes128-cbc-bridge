// Host test for the exact receiver safety helpers consumed by arduino_slave.

#include "../../../firmware/arduino_slave/ReceiverSafety.h"

#include <stdint.h>
#include <stdio.h>

using namespace ReceiverSafety;

static int g_run = 0;
static int g_failed = 0;

#define CHECK(expr)                                  \
  do {                                               \
    ++g_run;                                         \
    if (!(expr)) {                                   \
      ++g_failed;                                    \
      printf("FAIL line %d: %s\n", __LINE__, #expr); \
    }                                                \
  } while (0)

int main() {
  size_t out = 999;

  uint8_t pad1[16] = {0};
  pad1[15] = 1;
  CHECK(validPkcs7(pad1, 16, out) && out == 15);

  uint8_t pad7[16] = {0};
  for (int i = 9; i < 16; ++i) pad7[i] = 7;
  CHECK(validPkcs7(pad7, 16, out) && out == 9);

  uint8_t pad16[16];
  for (int i = 0; i < 16; ++i) pad16[i] = 16;
  CHECK(validPkcs7(pad16, 16, out) && out == 0);

  uint8_t zero[16] = {0};
  out = 77;
  CHECK(!validPkcs7(zero, 16, out) && out == 77);

  uint8_t large[16] = {0};
  large[15] = 17;
  out = 77;
  CHECK(!validPkcs7(large, 16, out) && out == 77);


  uint8_t mixed[16] = {0};
  for (int i = 12; i < 16; ++i) mixed[i] = 4;
  mixed[13] = 3;
  out = 77;
  CHECK(!validPkcs7(mixed, 16, out) && out == 77);

  out = 77;
  CHECK(!validPkcs7(pad1, 0, out) && out == 77);

  out = 77;
  CHECK(!validPkcs7(pad1, 15, out) && out == 77);

  CHECK(!timeoutExpired(1000u, 1499u, 500u));
  CHECK(timeoutExpired(1000u, 1500u, 500u));
  CHECK(timeoutExpired(1000u, 1501u, 500u));
  CHECK(!timeoutExpired(0xFFFFFF00u, 0x00000000u, 500u));
  CHECK(!timeoutExpired(0xFFFFFF00u, 0x000000F3u, 500u));
  CHECK(timeoutExpired(0xFFFFFF00u, 0x000000F4u, 500u));

  printf("checks run: %d, failed: %d\n", g_run, g_failed);
  if (g_failed == 0) puts("PASS: strict receiver padding and wrap-safe timeout");
  return g_failed == 0 ? 0 : 1;
}
