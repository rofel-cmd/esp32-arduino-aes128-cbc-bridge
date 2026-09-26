# Reproduction

## Hardware

Use a DOIT-compatible 30-pin ESP32, an ATmega328P Uno-compatible board, an HC-05 carrier, and the 1 kΩ / 2 kΩ receive divider shown in `hardware/schematic.pdf`. Confirm common ground on the receiver assembly. The ESP32 is a separate USB-powered endpoint and communicates wirelessly.

## Configuration

Edit `firmware/libraries/CapstoneConfig/src/CapstoneConfig.h` and replace the six zero bytes in `CAPSTONE_HC05_ADDRESS` with your own HC-05 address. The bundled key and PIN are public demonstration values.

## Build targets

- ESP32: `esp32:esp32:esp32doit-devkit-v1`
- Receiver: `MiniCore:avr:328:clock=16MHz_external,variant=modelP,bootloader=uart0`

Install the Arduino Cryptography Library and the appropriate ESP32 and MiniCore board packages. Add `firmware/libraries` to the Arduino library search path. Compile `firmware/esp32_master/esp32_master.ino` and `firmware/arduino_slave/arduino_slave.ino` separately. Do not place both sketches in one Arduino sketch directory.

For the host checks, install the dependencies from `pyproject.toml`, then run `tools/verify_public_repository.ps1` in PowerShell 7. The script does not upload firmware or access serial ports.

After flashing on your own hardware, open the receiver monitor at 9600 baud and the ESP32 monitor at 115200 baud. Wait for connection, then submit `ACTIVATE` and `DEACTIVATE` one at a time.
