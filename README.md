# Encrypted Bluetooth control-link capstone

This repository is a reviewable reference implementation of a two-board control link. A DOIT-compatible ESP32 sends framed AES-128-CBC messages over Bluetooth Classic SPP to an HC-05 attached to an ATmega328P receiver. Commands are correlated with CRC-protected responses and a bounded timeout.

The final dated six-command bench run observed six alternating commands, six matching responses, and a final `INACTIVE` state. Firmware-reported round-trip times ranged from 130 to 168 ms. Earlier bounded tests covered AES padding at 15, 16, and 17 bytes; a 255-byte accepted maximum and 256-byte sender refusal; repeated delivery; ESP32 restart; receiver power-cycle recovery; and one retained malformed-response timeout followed by two successful matches.

## What this demonstrates

- Confidentiality of the Bluetooth application payload using AES-128-CBC.
- A compact command/response grammar with CRC consistency checking and response correlation.
- A measured solderless prototype, documented schematic, BOM, firmware, and host-side tests.

It does not provide message authentication, replay protection, key exchange, production credential storage, range qualification, endurance qualification, or a safety-rated actuator. The shared key and pairing PIN in this repository are public demonstration values.

## Start here

1. Read [the reproduction guide](docs/reproduction.md).
2. Set the address of your own HC-05 in `firmware/libraries/CapstoneConfig/src/CapstoneConfig.h`.
3. Compile the sketches for the targets listed in the guide.
4. Run `tools/verify_public_repository.ps1` from PowerShell for the host checks and repository audit.

The repository is licensed under MIT for project-authored material. Third-party schematic assets retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
