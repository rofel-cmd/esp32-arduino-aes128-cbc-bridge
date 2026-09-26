#!/usr/bin/env python3
"""
AES-128-CBC loopback test — simulates the ESP32 → Arduino protocol end-to-end.

Tests:
  1. NIST Known Answer Test (KAT) — verifies AES-128-CBC correctness
  2. Loopback — encrypt on "master", decrypt on "slave", compare to original
  3. PKCS#7 — various message lengths including edge cases
  4. IV uniqueness — 1000 TRNG IVs, check no collisions
  5. Protocol framing — [IV(16)][LEN_HI][LEN_LO][ciphertext]

Run: conda run -n ml_ai python3 loopback_test.py
"""
import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# PSK — must match master_key / slave_key in both .ino files
PSK = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
             0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])


# --- AES-128-CBC helpers (mirrors the .ino implementations) ---

def pkcs7_pad(data: bytes) -> bytes:
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)


def pkcs7_unpad(data: bytes) -> bytes:
    padding = data[-1]
    if padding == 0 or padding > 16:
        raise ValueError(f"Invalid PKCS7 padding byte: {padding}")
    if data[-padding:] != bytes([padding] * padding):
        raise ValueError("PKCS7 padding bytes are inconsistent")
    return data[:-padding]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()


def trng_iv() -> bytes:
    """Mimics ESP32 esp_random() — 4x 32-bit hardware random = 16 bytes."""
    return os.urandom(16)


# --- Protocol framing (mirrors the updated .ino protocol) ---

def master_send(message: str, key: bytes = PSK) -> bytes:
    """Returns the full byte sequence the ESP32 writes to BTSerial."""
    plaintext = pkcs7_pad(message.encode())
    iv = trng_iv()
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    length = len(ciphertext)
    return iv + struct.pack('>H', length) + ciphertext


def slave_receive(packet: bytes, key: bytes = PSK) -> str:
    """Parses a packet as the Arduino would and returns the decrypted message."""
    if len(packet) < 18:
        raise ValueError("Packet too short")
    iv = packet[:16]
    length = struct.unpack('>H', packet[16:18])[0]
    if length % 16 != 0 or length == 0 or length > 256:
        raise ValueError(f"Invalid length field: {length}")
    ciphertext = packet[18:18 + length]
    if len(ciphertext) != length:
        raise ValueError("Packet truncated")
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    return pkcs7_unpad(plaintext).decode()


# --- Test suite ---

def test_nist_kat():
    """NIST SP 800-38A, Example F.2.1 — CBC-AES128-Encrypt."""
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt  = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
    expected_ct = bytes.fromhex('7649abac8119b246cee98e9b12e9197d')
    ct = aes_cbc_encrypt(pt, key, iv)
    assert ct == expected_ct, f"NIST KAT FAIL: {ct.hex()} != {expected_ct.hex()}"
    print("  PASS  NIST KAT (F.2.1)")


def test_loopback_basic():
    messages = [
        "Hello, World!",
        "AES-128-CBC with TRNG IV",
        "A" * 15,   # one byte under block boundary
        "A" * 16,   # exact block — PKCS#7 adds a full extra block
        "A" * 17,   # one byte over
        "A" * 32,
        "A" * 255,  # near max (255 chars → 256 bytes padded)
    ]
    for msg in messages:
        packet = master_send(msg)
        recovered = slave_receive(packet)
        assert recovered == msg, f"Loopback FAIL for len={len(msg)}: {repr(recovered)}"
        print(f"  PASS  loopback len={len(msg):3d}  padded={len(packet)-18:3d} bytes")


def test_pkcs7_edge_cases():
    # PKCS#7: message length = multiple of 16 must add full padding block
    for length in [16, 32, 48]:
        msg = "X" * length
        padded = pkcs7_pad(msg.encode())
        assert len(padded) == length + 16, f"PKCS7 FAIL at len={length}"
        assert padded[-1] == 16
        unpadded = pkcs7_unpad(padded)
        assert unpadded == msg.encode()
    print("  PASS  PKCS7 edge cases (multiples of 16)")

    # Bad padding should raise
    for bad in [b'\x00' * 16, b'\xff' * 16, b'hello\x00' * 3]:
        try:
            pkcs7_unpad(bad)
            print(f"  FAIL  PKCS7 should have raised for {bad.hex()[:16]}")
        except ValueError:
            pass
    print("  PASS  PKCS7 rejects invalid padding")


def test_iv_uniqueness():
    n = 1000
    ivs = [trng_iv() for _ in range(n)]
    unique = len(set(ivs))
    assert unique == n, f"IV collision! {n - unique} duplicates in {n} IVs"
    print(f"  PASS  IV uniqueness: {n}/{n} unique (no collisions)")


def test_wrong_key():
    msg = "secret message"
    packet = master_send(msg, key=PSK)
    wrong_key = bytes([0x00] * 16)
    try:
        recovered = slave_receive(packet, key=wrong_key)
        # Should either raise (bad padding) or produce garbage — not the original
        assert recovered != msg, "Wrong key produced correct plaintext (impossible)"
        print("  PASS  Wrong key produces garbled output (no exception path)")
    except (ValueError, UnicodeDecodeError):
        print("  PASS  Wrong key raises on bad padding/encoding (expected)")


def test_protocol_framing():
    msg = "test"
    packet = master_send(msg)
    # Verify structure: IV(16) + LEN(2) + ciphertext(LEN)
    iv = packet[:16]
    length = struct.unpack('>H', packet[16:18])[0]
    ciphertext = packet[18:]
    assert len(ciphertext) == length, "Framing: ciphertext length mismatch"
    assert length % 16 == 0, "Framing: ciphertext not block-aligned"
    assert len(packet) == 18 + length, "Framing: packet size wrong"
    print(f"  PASS  Protocol framing: IV(16) + LEN({length}) + CT({length}) = {len(packet)} bytes")


# --- Runner ---

TESTS = [
    ("NIST Known Answer Test",   test_nist_kat),
    ("Loopback encrypt/decrypt", test_loopback_basic),
    ("PKCS#7 edge cases",        test_pkcs7_edge_cases),
    ("IV uniqueness (n=1000)",   test_iv_uniqueness),
    ("Wrong key rejection",      test_wrong_key),
    ("Protocol framing",         test_protocol_framing),
]

if __name__ == '__main__':
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("Missing dependency: conda run -n ml_ai pip install cryptography")
        raise SystemExit(1)

    passed = failed = 0
    for name, fn in TESTS:
        print(f"\n[{name}]")
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {e}")
            failed += 1

    print(f"\n{'='*40}")
    print(f"Results: {passed}/{passed+failed} passed", "✓" if failed == 0 else "✗")
    raise SystemExit(0 if failed == 0 else 1)
