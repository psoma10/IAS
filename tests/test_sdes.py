import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.sdes import (
    decrypt_block,
    decrypt_byte,
    decrypt_bytes,
    encrypt_block,
    encrypt_byte,
    encrypt_bytes,
    generate_keys,
)

# A handful of distinct 10-bit keys used across the exhaustive round-trip tests.
SAMPLE_KEYS = [
    "1010000010",
    "0000000000",
    "1111111111",
    "1100011110",
]


def _all_8bit_strings():
    for value in range(256):
        yield format(value, "08b")


class TestGenerateKeysValidation(unittest.TestCase):
    def test_rejects_too_short(self):
        with self.assertRaises(ValueError):
            generate_keys("123")

    def test_rejects_non_binary_characters(self):
        with self.assertRaises(ValueError):
            generate_keys("101000001x")  # 10 chars, but one is not '0'/'1'

    def test_rejects_nine_bits(self):
        with self.assertRaises(ValueError):
            generate_keys("101000001")  # 9 bits, one short

    def test_rejects_eleven_bits(self):
        with self.assertRaises(ValueError):
            generate_keys("10100000101")  # 11 bits, one too many

    def test_rejects_non_binary_digit(self):
        with self.assertRaises(ValueError):
            generate_keys("101000021x")  # contains '2' and 'x'

    def test_accepts_valid_key(self):
        k1, k2 = generate_keys("1010000010")
        self.assertEqual(len(k1), 8)
        self.assertEqual(len(k2), 8)
        self.assertTrue(set(k1) <= {"0", "1"})
        self.assertTrue(set(k2) <= {"0", "1"})


class TestEncryptBlockValidation(unittest.TestCase):
    def setUp(self):
        self.k1, self.k2 = generate_keys("1010000010")

    def test_rejects_too_short(self):
        with self.assertRaises(ValueError):
            encrypt_block("1010", self.k1, self.k2)

    def test_rejects_too_long(self):
        with self.assertRaises(ValueError):
            encrypt_block("101000001", self.k1, self.k2)

    def test_rejects_non_binary(self):
        with self.assertRaises(ValueError):
            encrypt_block("1010x001", self.k1, self.k2)

    def test_decrypt_block_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            decrypt_block("bad", self.k1, self.k2)


class TestRoundTripExhaustive(unittest.TestCase):
    """Exhaustive round-trip: every 8-bit plaintext, against several keys."""

    def test_all_256_plaintexts_round_trip_for_each_key(self):
        for key10 in SAMPLE_KEYS:
            k1, k2 = generate_keys(key10)
            with self.subTest(key=key10):
                for plaintext in _all_8bit_strings():
                    ciphertext = encrypt_block(plaintext, k1, k2)
                    self.assertEqual(len(ciphertext), 8)
                    recovered = decrypt_block(ciphertext, k1, k2)
                    self.assertEqual(recovered, plaintext)

    def test_encryption_is_not_generally_identity(self):
        # Sanity check: encryption should actually change most blocks (not a no-op).
        k1, k2 = generate_keys("1010000010")
        differing = sum(
            1 for p in _all_8bit_strings() if encrypt_block(p, k1, k2) != p
        )
        self.assertGreater(differing, 200)  # overwhelming majority should differ


class TestByteLevelRoundTrip(unittest.TestCase):
    def test_encrypt_decrypt_byte_all_values(self):
        k1, k2 = generate_keys("1010000010")
        for value in range(256):
            cipher_val = encrypt_byte(value, k1, k2)
            self.assertTrue(0 <= cipher_val <= 255)
            recovered = decrypt_byte(cipher_val, k1, k2)
            self.assertEqual(recovered, value)

    def test_encrypt_byte_rejects_out_of_range(self):
        k1, k2 = generate_keys("1010000010")
        with self.assertRaises(ValueError):
            encrypt_byte(256, k1, k2)
        with self.assertRaises(ValueError):
            encrypt_byte(-1, k1, k2)


class TestBytesRoundTrip(unittest.TestCase):
    def test_round_trip_binary_sample(self):
        k1, k2 = generate_keys("1010000010")
        data = b"\x00\xff\x01\x80"
        ciphertext = encrypt_bytes(data, k1, k2)
        self.assertEqual(len(ciphertext), len(data))
        self.assertEqual(decrypt_bytes(ciphertext, k1, k2), data)

    def test_round_trip_ascii_text(self):
        k1, k2 = generate_keys("0111111101")
        data = "The quick brown fox jumps over the lazy dog. 42!".encode("ascii")
        ciphertext = encrypt_bytes(data, k1, k2)
        self.assertEqual(len(ciphertext), len(data))
        self.assertEqual(decrypt_bytes(ciphertext, k1, k2), data)

    def test_round_trip_empty_bytes(self):
        k1, k2 = generate_keys("1010000010")
        self.assertEqual(encrypt_bytes(b"", k1, k2), b"")
        self.assertEqual(decrypt_bytes(b"", k1, k2), b"")


if __name__ == "__main__":
    unittest.main()
