# Hardware package

`schematic.pdf` is the reviewed as-built drawing. `bom.md` records the parts and bounded identification details. `schematic-source` contains the KiCad 10 project plus only the symbol and footprint assets required by the drawing.

The receiver uses an ATmega328P Uno-compatible board and an HC-05 carrier. The Uno transmit line reaches HC-05 RX through a nominal 1 kΩ upper / 2 kΩ lower divider. The earlier measured divider values were 4.86 V input and 3.22 V output. HC-05 TX connects to the Uno software-serial receive input. The ESP32 uses its internal Bluetooth radio and is not electrically tied to the receiver assembly.

Before fabrication, verify imported carrier footprints against the physical boards and correct the recorded Arduino footprint property on R1. The drawing documents the prototype; it is not a fabrication release.
