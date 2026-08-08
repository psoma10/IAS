import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.caesar import decrypt, encrypt


class TestCaesarCipher(unittest.TestCase):
    def test_known_encryption(self):
        self.assertEqual(encrypt("HELLO", 3), "KHOOR")

    def test_round_trip(self):
        samples = [
            "Hello, World! 123",
            "The Quick Brown Fox Jumps Over 42 Lazy Dogs.",
            "MiXeD cAsE with punctuation!! & digits 007",
            "zzzZZZaaaAAA",
        ]
        for text in samples:
            for shift in (0, 1, 13, 25, 26, 100, -5):
                with self.subTest(text=text, shift=shift):
                    self.assertEqual(decrypt(encrypt(text, shift), shift), text)

    def test_shift_normalization(self):
        text = "Attack At Dawn"
        self.assertEqual(encrypt(text, 29), encrypt(text, 3))
        self.assertEqual(encrypt(text, -1), encrypt(text, 25))
        self.assertEqual(decrypt(text, 29), decrypt(text, 3))
        self.assertEqual(decrypt(text, -1), decrypt(text, 25))

    def test_empty_string(self):
        self.assertEqual(encrypt("", 5), "")
        self.assertEqual(decrypt("", 5), "")


if __name__ == "__main__":
    unittest.main()
