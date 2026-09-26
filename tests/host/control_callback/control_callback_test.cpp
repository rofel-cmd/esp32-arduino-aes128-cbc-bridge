// Host test for the shared ControlProtocol codec and pending-transaction logic.
//
// Non-aborting counting harness: every CHECK runs, failures are counted and
// their source line printed, and the process exits nonzero if any failed. The
// "checks run" line is a count gate against a silent short-circuit.
//
// Build and run: tests/host/control_callback/run.sh

#include "../../../firmware/libraries/ControlProtocol/src/ControlProtocol.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

using namespace ControlProtocol;

static int g_run = 0;
static int g_failed = 0;

#define CHECK(expr)                                    \
  do {                                                 \
    ++g_run;                                           \
    if (!(expr)) {                                     \
      ++g_failed;                                      \
      printf("FAIL line %d: %s\n", __LINE__, #expr);   \
    }                                                  \
  } while (0)

int main() {
  // --- checksum: CRC-16/CCITT-FALSE ---
  CHECK(crc16((const uint8_t *)"123456789", 9) == 0x29B1);  // canonical check value
  CHECK(crc16((const uint8_t *)"", 0) == 0xFFFF);           // no bytes -> init value

  // --- strict command grammar ---
  Command cmd;
  const char *input = "CMD|00000001|ACTIVATE";
  CHECK(parseCommand(input, strlen(input), cmd));
  CHECK(cmd.id == 1 && cmd.active);
  CHECK(!parseCommand("CMD|00000001|ACTIVATEjunk", 25, cmd));  // trailing junk
  CHECK(!parseCommand("CMD|00000000|ACTIVATE", 21, cmd));      // zero id
  CHECK(!parseCommand("CMD|zzzzzzzz|ACTIVATE", 21, cmd));      // non-hex id
  CHECK(!parseCommand("CMD|abcdef12|ACTIVATE", 21, cmd));      // lowercase hex rejected
  CHECK(!parseCommand("CMD|00000001|ACT\0IVATE", 21, cmd));    // embedded NUL
  CHECK(!parseCommand("cmd|00000001|ACTIVATE", 21, cmd));      // wrong prefix
  CHECK(!parseCommand("CMD|00000001|BOGUSVRB", 21, cmd));      // 8-char unknown verb
  CHECK(!parseCommand("CMD|00000001|BOGUSVERB0", 23, cmd));    // 10-char unknown verb
  CHECK(!parseCommand("CMD|00000001|ON", 15, cmd));            // below minimum length
  CHECK(!parseCommand("CMD|00000001", 12, cmd));               // too short
  CHECK(parseCommand("CMD|ABCDEF12|DEACTIVATE", 23, cmd));
  CHECK(cmd.id == 0xABCDEF12 && !cmd.active);

  // --- command formatting round trip ---
  char command[COMMAND_CAPACITY];
  char response[RESPONSE_CAPACITY];
  CHECK(formatCommand(command, sizeof(command), 7, true));
  CHECK(strcmp(command, "CMD|00000007|ACTIVATE") == 0);
  CHECK(formatCommand(command, sizeof(command), 0x1234ABCD, false));
  CHECK(strcmp(command, "CMD|1234ABCD|DEACTIVATE") == 0);
  CHECK(!formatCommand(command, 10, 7, true));  // buffer too small

  // --- response grammar / formatting round trip ---
  CHECK(formatCommand(command, sizeof(command), 7, true));
  const uint16_t crc = crc16((const uint8_t *)command, strlen(command));
  CHECK(formatResponse(response, sizeof(response), 7, true, crc));
  Reply reply;
  CHECK(parseResponse(response, strlen(response), reply));
  CHECK(reply.id == 7 && reply.active && reply.crc == crc);
  CHECK(formatResponse(response, sizeof(response), 7, false, 0x0A0B));
  CHECK(strcmp(response, "RSP|00000007|INACTIVE|0A0B") == 0);
  CHECK(parseResponse(response, strlen(response), reply));
  CHECK(reply.id == 7 && !reply.active && reply.crc == 0x0A0B);
  CHECK(!parseResponse("RSP|00000007|ACTIVE|ZZZZ", 23, reply));      // non-hex crc
  CHECK(!parseResponse("RSP|00000007|ACTIVE|0000junk", 27, reply));  // trailing junk
  CHECK(!parseResponse("RSP|00000007|ACTIVE|000", 23, reply));       // short crc
  CHECK(!parseResponse("RSP|00000000|ACTIVE|0000", 24, reply));      // zero id
  CHECK(!parseResponse("XSP|00000007|ACTIVE|0000", 24, reply));      // wrong prefix
  CHECK(!parseResponse("RSP|00000007|MAYBE|0000", 22, reply));       // unknown state
  CHECK(!formatResponse(response, 12, 7, true, crc));                // buffer too small

  // --- pending transaction: correlation, busy, timeout/wrap, recovery ---
  Pending pending;
  CHECK(!pending.matches(Reply{7, true, crc}));  // idle before begin
  CHECK(!pending.expired(999999));               // idle never expires
  CHECK(pending.begin(7, true, crc, 100));
  CHECK(!pending.begin(8, false, crc, 101));     // busy: rejected, not queued
  CHECK(!pending.matches(Reply{8, true, crc}));  // stale/wrong id
  CHECK(!pending.matches(Reply{7, false, crc}));               // wrong state
  CHECK(!pending.matches(Reply{7, true, (uint16_t)(crc ^ 1)}));  // wrong crc
  CHECK(pending.matches(Reply{7, true, crc}));
  CHECK(!pending.expired(3099));  // 2999 ms elapsed
  CHECK(pending.expired(3100));   // 3000 ms elapsed
  pending.clear();
  CHECK(!pending.matches(Reply{7, true, crc}));  // recovered to idle after timeout
  CHECK(pending.begin(8, false, 123, 0xFFFFF000u));
  CHECK(!pending.expired(0xFFFFF800u));  // 2048 ms elapsed, no wrap yet
  CHECK(pending.expired(0xFFFFFBB8u));   // exactly 3000 ms elapsed, no wrap
  CHECK(pending.expired(0x00000000u));   // 4096 ms elapsed across the millis() wrap
  pending.clear();
  CHECK(pending.begin(9, true, crc, 9000));
  CHECK(!pending.matches(Reply{7, true, crc}));  // stale id from a prior transaction
  pending.clear();
  CHECK(!pending.begin(0, true, crc, 9100));  // zero id refused on an idle Pending
  CHECK(pending.begin(1, true, crc, 9100));   // nonzero id still arms

  printf("checks run: %d, failed: %d\n", g_run, g_failed);
  if (g_failed == 0) {
    puts("PASS: command/response grammar, CRC, correlation, busy, timeout/wrap and recovery");
  }
  return g_failed == 0 ? 0 : 1;
}
