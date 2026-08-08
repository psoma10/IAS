"""Caesar cipher: a mono-alphabetic substitution cipher.

Each alphabetic character is shifted a fixed number of positions along
the alphabet (A-Z / a-z wrap around using modulo 26); case is preserved
and non-alphabetic characters (digits, spaces, punctuation) pass through
unchanged. Encryption shifts forward by `shift`; decryption shifts
forward by `-shift`, which undoes it. Since -shift mod 26 is the same
as (26 - shift) mod 26, decrypt(encrypt(text, s), s) always returns text.
"""

ALPHABET_SIZE = 26


def _shift_char(char: str, shift: int) -> str:
    if char.isupper():
        base = ord("A")
    elif char.islower():
        base = ord("a")
    else:
        return char
    return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)


def encrypt(plaintext: str, shift: int) -> str:
    shift = shift % ALPHABET_SIZE
    return "".join(_shift_char(ch, shift) for ch in plaintext)


def decrypt(ciphertext: str, shift: int) -> str:
    shift = shift % ALPHABET_SIZE
    return "".join(_shift_char(ch, -shift) for ch in ciphertext)
