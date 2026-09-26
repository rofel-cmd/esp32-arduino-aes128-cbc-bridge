# As-built assembly BOM

This inventory covers the breadboard receiver and wireless ESP32 endpoint used in our September 14 six-command test. Electrical references match the as-built schematic netlist.

| Reference / assembly item | Quantity | Specification and role | Identification detail |
|---|---:|---|---|
| A1 | 1 | ATmega328P Uno-compatible receiver | Runtime device signature `1E 95 0F`. Clone manufacturer and carrier revision unidentified. The Uno R3 schematic symbol represents logical interfaces; header geometry is unspecified. |
| U1 | 1 | DOIT-compatible 30-pin ESP32 carrier; internal Classic Bluetooth; CH340C, USB-C | Our board reported ESP32-D0WD-V3 and 4 MB flash. Exact carrier manufacturer/part number unidentified. This endpoint uses its internal radio. |
| U2 | 1 | HC-05 six-pin carrier; receiver Bluetooth/UART interface | Use the address printed or reported by your own module. Carrier input is labelled 3.6–6 V and operated from Arduino 5 V. Manufacturer, firmware version and carrier revision unidentified; EN/STATE open. |
| R2 | 1 | 1 kΩ ±1%, five-band axial resistor; D11 to RX junction | We identified brown-black-black-brown-brown bands. Wattage, material, body size and manufacturer remain unspecified. |
| R1, R3 | 2 | Each 1 kΩ ±1%, five-band axial resistor; junction through R1 then R3 to receiver ground | Same provenance/specification as R2. Two series parts form nominal 2 kΩ lower leg. |
| Receiver breadboard | 1 assembly; board count unspecified | Solderless breadboard/rails supporting HC-05 and divider | The HC-05 and divider were assembled on solderless rails. Hole count, manufacturer and rail segmentation unidentified. |
| Jumper leads | 1 set; lead count unspecified | D11/input, RX junction, TXD/D10, VCC/5V, module GND, supply/ground rail distribution | The wiring record establishes connections rather than a physical lead count; lengths, gauges and terminal styles remain unspecified. |
| USB leads | 2 for simultaneous bench operation; present inventory uncounted | One lead to each board for onboard USB power and serial access | Separate board power and simultaneous serial streams were recorded. ESP32 uses USB-C; receiver and host-end connector types remain unidentified. |
| USB power/host source | Bench host supply; count unspecified | Powers boards through their onboard USB interfaces | September 14 test used host USB power; accepted schematic supply rails are labelled 5 V. |

Approximate design envelopes: receiver 11 × 9 × 5 cm; ESP32 endpoint 6 × 3.5 × 2 cm.

The divider ratio is nominally 2/3. We measured 4.86 V at its input and 3.22 V at its output in the earlier bench setup. Receiver, module and divider share ground; the ESP32 communicates wirelessly from a separate power/ground assembly.

Board-integrated components are counted within their assemblies. This inventory defines the solderless bench prototype's electrical parts. Before using the KiCad drawing for fabrication, correct R1's Arduino footprint property and verify the imported board footprints against measured carrier dimensions.
