# Results

The strongest dated bench result is the 2026-09-14 six-command smoke test. It recorded six alternating commands, six matching responses, consistent identifiers and states, no command errors, and a final `INACTIVE` state. Firmware-reported RTTs were 139, 142, 130, 138, 168, and 142 ms.

Additional bounded observations are represented in `tests/evidence`:

- 15-, 16-, and 17-byte plaintexts crossed the AES block boundary correctly.
- A 255-byte plaintext was delivered exactly; a 256-byte input was refused by the sender.
- Three distinct encrypted messages were delivered in order on one connection.
- Delivery resumed after an ESP32 restart and after a receiver/HC-05 power cycle.
- On 2026-09-11, one response was classified as malformed and timed out; after reset, two subsequent transactions matched.

Run `tests/evidence/verify_results.py` to recompute the reported aggregates from the public JSON records.
