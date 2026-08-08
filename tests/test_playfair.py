import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from algorithms.playfair import build_key_square, decrypt, encrypt


class TestKeySquare(unittest.TestCase):
    def test_monarchy_key_square(self):
        expected = [
            list("MONAR"),
            list("CHYBD"),
            list("EFGIK"),
            list("LPQST"),
            list("UVWXZ"),
        ]
        self.assertEqual(build_key_square("MONARCHY"), expected)


class TestEncryptKnownExample(unittest.TestCase):
    def test_monarchy_instruments(self):
        # Traced by hand against the MONARCHY key square above:
        # IN ST RU ME NT SX -> GA TL MZ CL RQ XA
        self.assertEqual(encrypt("INSTRUMENTS", "MONARCHY"), "GATLMZCLRQXA")

    def test_decrypt_reverses_known_example(self):
        # Decrypt recovers the original plus the trailing 'X' that encrypt()
        # padded on, since decrypt has no way to know it was padding.
        self.assertEqual(decrypt("GATLMZCLRQXA", "MONARCHY"), "INSTRUMENTSX")


class TestRoundTrip(unittest.TestCase):
    # Playfair round-trip only reproduces the original text exactly when
    # the plaintext has even length and no repeated letter within a
    # digraph, since otherwise encrypt() inserts an 'X' that decrypt()
    # cannot distinguish from a real letter. The samples below satisfy
    # that so decrypt(encrypt(x)) == x holds exactly.
    def test_round_trip_exact(self):
        samples = [
            ("ATTACKATDAWN", "KEYWORD"),
            ("PLAYFAIRCIPHER", "SECRET"),
            ("CRYPTOGRAPHYLABS", "CIPHER"),
        ]
        for plaintext, key in samples:
            with self.subTest(plaintext=plaintext, key=key):
                self.assertEqual(decrypt(encrypt(plaintext, key), key), plaintext)


class TestInputValidation(unittest.TestCase):
    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            decrypt("HELLO", "123")

    def test_empty_plaintext_raises(self):
        with self.assertRaises(ValueError):
            encrypt("", "KEY")
        with self.assertRaises(ValueError):
            encrypt("123", "KEY")

    def test_empty_ciphertext_raises(self):
        with self.assertRaises(ValueError):
            decrypt("", "KEY")


if __name__ == "__main__":
    unittest.main()
