"""
Tests for the SDES file-transfer building blocks: fileutils helpers and
byte-level round-trip correctness/integrity verification, plus a full
check against the real sample files committed under files/.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algorithms import sdes
from fileutils import preview_hex, sha256_hex

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_1MB = os.path.join(PROJECT_ROOT, "files", "client", "sample_1mb.bin")
SAMPLE_10KB = os.path.join(PROJECT_ROOT, "files", "server", "sample_10kb.bin")
KEY10 = "1010000010"


class TestFileUtils(unittest.TestCase):
    def test_sha256_hex_known_value(self):
        # SHA-256 of the empty byte string is a well-known constant.
        self.assertEqual(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_preview_hex_truncates_and_marks_continuation(self):
        data = bytes(range(64))
        preview = preview_hex(data, num_bytes=8)
        self.assertTrue(preview.endswith("..."))
        self.assertEqual(preview.split(" ...")[0], data[:8].hex(" "))

    def test_preview_hex_no_ellipsis_when_short(self):
        data = bytes([1, 2, 3])
        self.assertEqual(preview_hex(data, num_bytes=8), data.hex(" "))


class TestSdesByteRoundTrip(unittest.TestCase):
    def setUp(self):
        self.k1, self.k2 = sdes.generate_keys(KEY10)

    def test_round_trip_and_hash_match_on_random_bytes(self):
        random.seed(123)
        original = random.randbytes(5000)

        ciphertext = sdes.encrypt_bytes(original, self.k1, self.k2)
        self.assertNotEqual(ciphertext, original)

        decrypted = sdes.decrypt_bytes(ciphertext, self.k1, self.k2)
        self.assertEqual(decrypted, original)
        self.assertEqual(sha256_hex(decrypted), sha256_hex(original))

    def test_round_trip_preserves_length_no_padding_needed(self):
        # SDES block size is exactly 8 bits = 1 byte, so every byte is
        # already a complete block: ciphertext length == plaintext length.
        original = bytes(range(256))
        ciphertext = sdes.encrypt_bytes(original, self.k1, self.k2)
        self.assertEqual(len(ciphertext), len(original))


class TestSampleFilesIntegrity(unittest.TestCase):
    """Exercises the exact files used by the live 1MB / 10KB transfers."""

    def test_1mb_sample_file_present_and_correct_size(self):
        self.assertTrue(os.path.isfile(SAMPLE_1MB), f"missing {SAMPLE_1MB}")
        self.assertEqual(os.path.getsize(SAMPLE_1MB), 1_048_576)

    def test_10kb_sample_file_present_and_correct_size(self):
        self.assertTrue(os.path.isfile(SAMPLE_10KB), f"missing {SAMPLE_10KB}")
        self.assertEqual(os.path.getsize(SAMPLE_10KB), 10 * 1024)

    def test_10kb_sample_round_trips_through_sdes(self):
        k1, k2 = sdes.generate_keys(KEY10)
        with open(SAMPLE_10KB, "rb") as f:
            original = f.read()

        ciphertext = sdes.encrypt_bytes(original, k1, k2)
        decrypted = sdes.decrypt_bytes(ciphertext, k1, k2)

        self.assertEqual(decrypted, original)
        self.assertEqual(sha256_hex(decrypted), sha256_hex(original))


if __name__ == "__main__":
    unittest.main()
