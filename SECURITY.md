# Security scope

This prototype encrypts application payloads with AES-128-CBC. It provides confidentiality against casual observation of the Bluetooth payload, within the limits of a public demonstration key.

There is no authentication and no replay protection. CRC fields detect accidental corruption; they are not cryptographic integrity checks. An attacker who knows the key can forge traffic, and CBC ciphertext can be modified without reliable detection. The fixed demonstration key and pairing PIN `1234` are public and must not be used as secrets.

For a deployed system, replace this construction with an authenticated-encryption protocol, unique per-device credentials, replay counters or nonces, protected provisioning, and a threat model appropriate to the actuator and environment.
