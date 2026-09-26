# Protocol

The ESP32 accepts `ACTIVATE` or `DEACTIVATE` from its USB serial console. It creates a command identifier, builds a `CMD|id|verb|crc` record, encrypts and frames that record, and sends it over Bluetooth SPP. Only one command may be outstanding. The receiver decrypts a complete frame, validates padding and grammar, updates its simulated state, and returns `RSP|id|ACTIVE|crc` or `RSP|id|INACTIVE|crc` through the same encrypted framing.

Each encrypted frame is a two-byte big-endian ciphertext length, a 16-byte IV, and AES-128-CBC ciphertext. Plaintext uses PKCS#7 padding. The sender caps plaintext at 255 bytes so the receiver's fixed buffers remain bounded.

The response identifier must match the outstanding command. The sender reports a match and round-trip time, or a timeout after 3000 ms. CRC-16 provides corruption detection only; it is not authentication.
