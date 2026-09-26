#ifndef CAPSTONE_CONFIG_H
#define CAPSTONE_CONFIG_H

#include <stdint.h>

// Replace this zero placeholder with the address of your own HC-05 module.
static uint8_t CAPSTONE_HC05_ADDRESS[6] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Public demonstration value. It is not a deployment credential.
static const char CAPSTONE_PAIRING_PIN[] = "1234";

// Public demonstration value from a published AES example. Replace it for any
// system that requires confidentiality outside this reproducible demonstration.
static uint8_t CAPSTONE_AES128_DEMO_KEY[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

#endif  // CAPSTONE_CONFIG_H

